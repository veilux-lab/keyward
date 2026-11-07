package mcpconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Claude changes Claude Code's MCP servers through its own CLI, so a running
// Claude Code does not write its old copy of ~/.claude.json over the change.
type Claude struct {
	Path string
	// Run executes argv, whose first element is the program, in dir.
	Run           func(dir string, argv ...string) ([]byte, error)
	Home, Workdir string
	// Keyward is keyward's full path, written in place of a bare "keyward":
	// Claude Code started outside a shell may not have it on PATH.
	Keyward string
}

// FindClaude accepts the claude at path only if it can add a server from JSON,
// which is what keeps every field of a definition.
func FindClaude(path string, run func(string, ...string) ([]byte, error)) (Claude, bool) {
	if path == "" {
		return Claude{}, false
	}
	out, err := run("", path, "mcp", "--help")
	if err != nil || !strings.Contains(string(out), "add-json") {
		return Claude{}, false
	}
	return Claude{Path: path, Run: run}, true
}

// Commands shows what Apply will run, with literal env and header values hidden,
// and what may be a secret in its args.
func (c Claude) Commands(f Finding) []string {
	def, _, err := c.definitions(f)
	if err != nil {
		return []string{"(cannot read " + f.Name + ": " + err.Error() + ")"}
	}
	return []string{
		fmt.Sprintf("claude mcp remove %s -s %s", f.Name, f.Scope),
		fmt.Sprintf("claude mcp add-json %s %s -s %s", f.Name, singleQuoted(printable(def)), f.Scope),
	}
}

// Apply replaces the server with f.Want, puts the original back if adding fails,
// and reads the config back to check the change landed.
func (c Claude) Apply(f Finding) error {
	def, original, err := c.definitions(f)
	if err != nil {
		return err
	}
	dir := c.dir(f)
	if out, err := c.Run(dir, c.Path, "mcp", "remove", f.Name, "-s", f.Scope); err != nil {
		return fmt.Errorf("claude mcp remove %s: %v: %s", f.Name, err, strings.TrimSpace(string(out)))
	}
	if out, err := c.Run(dir, c.Path, "mcp", "add-json", f.Name, string(def), "-s", f.Scope); err != nil {
		failure := fmt.Errorf("claude mcp add-json %s: %v: %s", f.Name, err, strings.TrimSpace(string(out)))
		if out, err := c.Run(dir, c.Path, "mcp", "add-json", f.Name, string(original), "-s", f.Scope); err != nil {
			// Typed into claude mcp add-json, the values would stay in shell history.
			// With Claude Code closed, it cannot write its old copy over the edit.
			return fmt.Errorf("%w; putting the original back also failed (%s), and removing it deleted the values shown as hidden. "+
				"With Claude Code closed, put it back in the mcpServers of %s, with those values filled in: %s: %s",
				failure, strings.TrimSpace(string(out)), f.Config, quoteJSON(f.Name), printable(original))
		}
		return fmt.Errorf("%w; the original definition was put back", failure)
	}
	return c.check(f)
}

// Credentials names the fields of f that hold a credential doctor reports in env
// or headers, in its current definition or, failing that, the one Apply would add.
// claude mcp add-json gets either in its command line, which any process can
// read, so Apply must not be run for f while there is one.
func (c Claude) Credentials(f Finding) []string {
	updated, original, err := c.definitions(f)
	if err != nil {
		return nil
	}
	for _, def := range [][]byte{original, updated} {
		var s jsonServer
		if json.Unmarshal(def, &s) != nil {
			continue
		}
		var fields []string
		for _, l := range Literals(fromJSON("Claude Code", "", "", map[string]jsonServer{f.Name: s})) {
			if l.Secret && (strings.HasPrefix(l.Field, "env.") || strings.HasPrefix(l.Field, "headers.")) {
				fields = append(fields, l.Field)
			}
		}
		if len(fields) > 0 {
			return fields
		}
	}
	return nil
}

// definitions returns the new definition and the current one, as JSON. Fields
// keyward does not set are kept; a remote server's url, headers, and type go,
// because it now starts locally.
func (c Claude) definitions(f Finding) (updated, original []byte, err error) {
	current, err := c.current(f)
	if err != nil {
		return nil, nil, err
	}
	original, err = json.Marshal(current)
	if err != nil {
		return nil, nil, err
	}
	next := map[string]any{}
	for k, v := range current {
		next[k] = v
	}
	if _, remote := next["url"]; remote {
		delete(next, "url")
		delete(next, "headers")
		delete(next, "type")
	}
	next["command"] = c.command(f.Want.Command)
	next["args"] = f.Want.Args
	if len(f.Want.Env) > 0 {
		next["env"] = f.Want.Env
	} else {
		delete(next, "env")
	}
	updated, err = json.Marshal(next)
	return updated, original, err
}

func (c Claude) command(name string) string {
	if name == "keyward" && c.Keyward != "" {
		return c.Keyward
	}
	return name
}

// dir is where claude changes f: the folder of the project a local or project
// server is in, as Claude Code's CLI changes such a server only when run there.
func (c Claude) dir(f Finding) string {
	if f.Scope != "user" && f.Project != "" {
		return f.Project
	}
	return c.Workdir
}

// current reads the server's definition exactly as Claude Code stores it.
func (c Claude) current(f Finding) (map[string]any, error) {
	path := filepath.Join(c.Home, ".claude.json")
	if f.Scope == "project" {
		path = filepath.Join(c.dir(f), ".mcp.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]map[string]any `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	servers := doc.MCPServers
	if f.Scope == "local" {
		servers = doc.Projects[c.dir(f)].MCPServers
	}
	def, ok := servers[f.Name]
	if !ok {
		return nil, fmt.Errorf("%s has no server %q", path, f.Name)
	}
	return def, nil
}

func (c Claude) check(f Finding) error {
	servers, _ := Load(c.Home, c.dir(f))
	i := slices.IndexFunc(servers, func(s Server) bool {
		return s.Client == "Claude Code" && s.Scope == f.Scope && s.Name == f.Name
	})
	if i < 0 {
		return fmt.Errorf("claude reported success, but %s is no longer configured", f.Name)
	}
	if got := servers[i]; got.Command != c.command(f.Want.Command) || !slices.Equal(got.Args, f.Want.Args) {
		return fmt.Errorf("claude reported success, but %s starts with %s %v", f.Name, got.Command, shownArgs(got.Args))
	}
	return nil
}

// printable is a JSON definition for the user to read, with each literal env and
// header value hidden, and what may be a secret in its url and args.
func printable(def []byte) string {
	var printed map[string]any
	json.Unmarshal(def, &printed)
	for _, field := range []string{"env", "headers"} {
		values, _ := printed[field].(map[string]any)
		for k, v := range values {
			if s, ok := v.(string); ok {
				values[k] = shown(s)
			}
		}
	}
	if url, ok := printed["url"].(string); ok {
		printed["url"] = shownArg(url)
	}
	args, _ := printed["args"].([]any)
	words := make([]string, len(args))
	for i, a := range args {
		words[i], _ = a.(string)
	}
	for i, w := range shownArgs(words) {
		if w != words[i] {
			args[i] = w
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(printed)
	return strings.TrimSuffix(b.String(), "\n")
}

// singleQuoted is s as one literal shell word, so a ${VAR} in it is not expanded.
func singleQuoted(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
