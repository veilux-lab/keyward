package mcpconfig

import (
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

// Commands shows what Apply will run.
func (c Claude) Commands(f Finding) []string {
	def, _, err := c.definitions(f)
	if err != nil {
		return []string{"(cannot read " + f.Name + ": " + err.Error() + ")"}
	}
	return []string{
		fmt.Sprintf("claude mcp remove %s -s %s", f.Name, f.Scope),
		fmt.Sprintf("claude mcp add-json %s %s -s %s", f.Name, singleQuoted(string(def)), f.Scope),
	}
}

// Apply replaces the server with f.Want, puts the original back if adding fails,
// and reads the config back to check the change landed.
func (c Claude) Apply(f Finding) error {
	def, original, err := c.definitions(f)
	if err != nil {
		return err
	}
	if out, err := c.Run(c.Workdir, c.Path, "mcp", "remove", f.Name, "-s", f.Scope); err != nil {
		return fmt.Errorf("claude mcp remove %s: %v: %s", f.Name, err, strings.TrimSpace(string(out)))
	}
	if out, err := c.Run(c.Workdir, c.Path, "mcp", "add-json", f.Name, string(def), "-s", f.Scope); err != nil {
		failure := fmt.Errorf("claude mcp add-json %s: %v: %s", f.Name, err, strings.TrimSpace(string(out)))
		if out, err := c.Run(c.Workdir, c.Path, "mcp", "add-json", f.Name, string(original), "-s", f.Scope); err != nil {
			return fmt.Errorf("%w; putting the original back also failed, so add it yourself: claude mcp add-json %s %s -s %s (%s)",
				failure, f.Name, singleQuoted(string(original)), f.Scope, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("%w; the original definition was put back", failure)
	}
	return c.check(f)
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

// current reads the server's definition exactly as Claude Code stores it.
func (c Claude) current(f Finding) (map[string]any, error) {
	path := filepath.Join(c.Home, ".claude.json")
	if f.Scope == "project" {
		path = filepath.Join(c.Workdir, ".mcp.json")
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
		servers = doc.Projects[c.Workdir].MCPServers
	}
	def, ok := servers[f.Name]
	if !ok {
		return nil, fmt.Errorf("%s has no server %q", path, f.Name)
	}
	return def, nil
}

func (c Claude) check(f Finding) error {
	servers, _ := Load(c.Home, c.Workdir)
	i := slices.IndexFunc(servers, func(s Server) bool {
		return s.Client == "Claude Code" && s.Scope == f.Scope && s.Name == f.Name
	})
	if i < 0 {
		return fmt.Errorf("claude reported success, but %s is no longer configured", f.Name)
	}
	if got := servers[i]; got.Command != c.command(f.Want.Command) || !slices.Equal(got.Args, f.Want.Args) {
		return fmt.Errorf("claude reported success, but %s starts with %s %v", f.Name, got.Command, got.Args)
	}
	return nil
}

// singleQuoted is s as one literal shell word, so a ${VAR} in it is not expanded.
func singleQuoted(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
