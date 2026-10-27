// Package mcpconfig finds MCP servers that read a variable keyward has turned into
// a cap:// reference, and writes the configuration that fixes each one.
//
// It never edits a config. Those files belong to their tools, which may rewrite
// them while running, so keyward prints the replacement and the user applies it.
package mcpconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/migrate"
)

// Server is one MCP server definition, from any supported client.
type Server struct {
	Client, Config, Name string

	Command string
	Args    []string
	Env     map[string]string

	// URL and Headers describe a remote server; header values may hold ${VAR}.
	URL     string
	Headers map[string]string

	// PassEnv names variables the client copies from its own environment (Codex).
	PassEnv []string

	// Scope is where Claude Code keeps the server: user, local, or project.
	Scope string

	toml        bool
	timeout     string
	headerTable string
	disabled    bool
}

// Finding is a server that would receive a cap:// reference instead of a value.
type Finding struct {
	Server
	// Vars are the variables it reads that now hold references, sorted.
	Vars []string
	// Suggestion is the replacement definition, in the client's own format.
	Suggestion string
	// Note says where the suggestion goes.
	Note string
	// Want is the suggested definition, for applying it rather than printing it.
	Want Definition
	// Exposed marks a server that already runs through keyward but puts its secrets
	// in a command line, which any process can read.
	Exposed bool
}

// Definition is how a stdio server is started.
type Definition struct {
	Command string
	Args    []string
	Env     map[string]string
}

// References maps each variable assigned a cap:// reference in files to its name.
func References(files []string) map[string]string {
	refs := map[string]string{}
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, a := range migrate.Scan(content).Assignments {
			if h, err := handle.Parse(a.Value); err == nil {
				refs[a.Name] = h.Name
			}
		}
	}
	return refs
}

// Load reads every supported client configuration that exists. A file that
// cannot be read is reported, never guessed at.
func Load(home, workdir string) ([]Server, []error) {
	var servers []Server
	var errs []error
	add := func(found []Server, err error) {
		servers = append(servers, found...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(loadClaude(filepath.Join(home, ".claude.json"), workdir))
	add(loadJSON("Claude Code", filepath.Join(workdir, ".mcp.json"), "project"))
	add(loadCodex(filepath.Join(home, ".codex", "config.toml")))
	add(loadJSON("Cursor", filepath.Join(home, ".cursor", "mcp.json"), ""))
	if workdir != home {
		add(loadJSON("Cursor", filepath.Join(workdir, ".cursor", "mcp.json"), ""))
	}
	return servers, errs
}

type jsonServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func readJSON(path string, into any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err == nil {
		err = json.Unmarshal(data, into)
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

func fromJSON(client, config, scope string, servers map[string]jsonServer) []Server {
	var out []Server
	for name, s := range servers {
		out = append(out, Server{Client: client, Config: config, Name: name, Scope: scope,
			Command: s.Command, Args: s.Args, Env: s.Env, URL: s.URL, Headers: s.Headers})
	}
	return out
}

// loadClaude reads user-scope servers and the current project's.
func loadClaude(path, workdir string) ([]Server, error) {
	var file struct {
		MCPServers map[string]jsonServer `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]jsonServer `json:"mcpServers"`
		} `json:"projects"`
	}
	if ok, err := readJSON(path, &file); !ok {
		return nil, err
	}
	servers := fromJSON("Claude Code", path, "user", file.MCPServers)
	if p, ok := file.Projects[workdir]; ok {
		servers = append(servers, fromJSON("Claude Code", path+" (project "+workdir+")", "local", p.MCPServers)...)
	}
	return servers, nil
}

func loadJSON(client, path, scope string) ([]Server, error) {
	var file struct {
		MCPServers map[string]jsonServer `json:"mcpServers"`
	}
	if ok, err := readJSON(path, &file); !ok {
		return nil, err
	}
	return fromJSON(client, path, scope, file.MCPServers), nil
}

func loadCodex(path string) ([]Server, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tables, err := readTOML(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var servers []Server
	for key, t := range tables {
		parts := strings.Split(key, "\x00")
		if len(parts) != 2 || parts[0] != "mcp_servers" {
			continue
		}
		s := Server{Client: "Codex", Config: path, Name: parts[1], toml: true, Env: map[string]string{}, Headers: map[string]string{}}
		s.Command, _ = t["command"].(string)
		s.Args, _ = t["args"].([]string)
		s.URL, _ = t["url"].(string)
		s.PassEnv, _ = t["env_vars"].([]string)
		if v, ok := t["startup_timeout_sec"].(rawValue); ok {
			s.timeout = string(v)
		}
		s.disabled = t["enabled"] == rawValue("false")
		env, _ := t["env"].(map[string]string)
		if sub := tables[key+"\x00env"]; sub != nil {
			env = stringsOf(sub)
		}
		for k, v := range env {
			s.Env[k] = v
		}
		if v, ok := t["bearer_token_env_var"].(string); ok {
			s.Headers["Authorization"] = "Bearer ${" + v + "}"
		}
		headers, _ := t["env_http_headers"].(map[string]string)
		if sub := tables[key+"\x00env_http_headers"]; sub != nil {
			headers = stringsOf(sub)
			s.headerTable = "[mcp_servers." + tomlKey(parts[1]) + ".env_http_headers]"
		}
		for h, v := range headers {
			s.Headers[h] = "${" + v + "}"
		}
		servers = append(servers, s)
	}
	return servers, nil
}

func stringsOf(t map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range t {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// placeholder matches ${VAR}, ${VAR:-default}, and Cursor's ${env:VAR}.
var placeholder = regexp.MustCompile(`\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}`)

func runsThroughKeyward(s Server) bool {
	return filepath.Base(s.Command) == "keyward" && len(s.Args) > 0 && s.Args[0] == "run"
}

// Check returns the servers that would receive a reference, with their fixes.
func Check(servers []Server, refs map[string]string) []Finding {
	var findings []Finding
	for _, s := range servers {
		exposed := false
		if bridge, ok := exposingBridge(s); ok {
			s, exposed = bridge, true
		}
		if s.disabled || runsThroughKeyward(s) {
			continue
		}
		used := map[string]string{}
		note := func(text string) {
			for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
				if ref, ok := refs[m[1]]; ok {
					used[m[1]] = ref
				}
			}
		}
		note(s.Command)
		note(s.URL)
		for _, a := range s.Args {
			note(a)
		}
		for _, v := range s.Headers {
			note(v)
		}
		for k, v := range s.Env {
			note(v)
			if h, err := handle.Parse(v); err == nil {
				used[k] = h.Name
			}
		}
		for _, v := range s.PassEnv {
			if ref, ok := refs[v]; ok {
				used[v] = ref
			}
		}
		if len(used) == 0 {
			continue
		}
		f := Finding{Server: s, Exposed: exposed}
		for v := range used {
			f.Vars = append(f.Vars, v)
		}
		slices.Sort(f.Vars)
		f.Suggestion, f.Note, f.Want = suggest(s, used)
		findings = append(findings, f)
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		return strings.Compare(a.Client+a.Config+a.Name, b.Client+b.Config+b.Name)
	})
	return findings
}

// suggest wraps the server in keyward run. A remote server goes through the
// mcp-remote bridge, so that its headers are filled in by the local process.
func suggest(s Server, used map[string]string) (string, string, Definition) {
	inner := append([]string{s.Command}, s.Args...)
	var headers []int
	if s.URL != "" {
		inner = []string{"npx", "-y", "mcp-remote", s.URL}
		names := make([]string, 0, len(s.Headers))
		for h := range s.Headers {
			names = append(names, h)
		}
		slices.Sort(names)
		for _, h := range names {
			inner = append(inner, "--header", h+": "+s.Headers[h])
			headers = append(headers, len(inner)-1)
		}
		inner = append(inner, "--transport", "http-only")
	}
	env := map[string]string{}
	for k, v := range s.Env {
		env[k] = v
	}
	for v, ref := range used {
		env[v] = handle.Prefix + ref
	}
	// A value that is exactly one placeholder becomes a reference keyward resolves.
	for k, v := range env {
		if m := placeholder.FindStringSubmatch(v); m != nil && m[0] == v {
			if ref, ok := used[m[1]]; ok {
				env[k] = handle.Prefix + ref
			}
		}
	}
	// The server gets only its own secrets, not every reference the client inherited.
	var only []string
	for k, v := range env {
		if strings.HasPrefix(v, handle.Prefix) {
			only = append(only, k)
		}
	}
	slices.Sort(only)
	args := []string{"run", "--only", strings.Join(only, ","), "--"}
	if slices.ContainsFunc(inner, placeholder.MatchString) {
		args = append(args, "sh", "-c", "exec "+shellWords(inner, headers))
	} else {
		args = append(args, inner...)
	}
	want := Definition{Command: "keyward", Args: args, Env: env}
	if s.toml {
		return tomlServer(s, "keyward", args, env, nil), tomlNote(s), want
	}
	return jsonServerText(s.Name, "keyward", args, env), "Replace the " + quoteJSON(s.Name) + " entry in " + s.Config + ".", want
}

// Undo returns each server that starts through keyward, with the definition that
// starts it directly, reading its secrets from the environment the client starts
// with. Vars names those secrets, which must hold real values again.
func Undo(servers []Server) []Finding {
	var findings []Finding
	for _, s := range servers {
		if s.disabled || !runsThroughKeyward(s) {
			continue
		}
		inner := wrappedCommand(s)
		if len(inner) == 0 {
			continue
		}
		f := Finding{Server: s}
		env := map[string]string{}
		for k, v := range s.Env {
			if !handle.IsRef(v) {
				env[k] = v
				continue
			}
			f.Vars = append(f.Vars, k)
			// Each client has its own syntax for a value taken from its environment.
			switch {
			case s.toml:
			case s.Client == "Cursor":
				env[k] = "${env:" + k + "}"
			default:
				env[k] = "${" + k + "}"
			}
		}
		slices.Sort(f.Vars)
		f.Want = Definition{Command: inner[0], Args: inner[1:], Env: env}
		if s.toml {
			f.Suggestion = tomlServer(s, inner[0], inner[1:], env, f.Vars)
			f.Note = tomlNote(s)
		} else {
			f.Suggestion = jsonServerText(s.Name, inner[0], inner[1:], env)
			f.Note = "Replace the " + quoteJSON(s.Name) + " entry in " + s.Config + "."
		}
		findings = append(findings, f)
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		return strings.Compare(a.Client+a.Config+a.Name, b.Client+b.Config+b.Name)
	})
	return findings
}

// wrappedCommand is the command a keyward-wrapped server starts, after keyward
// run and its options.
func wrappedCommand(s Server) []string {
	inner := s.Args[1:]
	if len(inner) > 1 && inner[0] == "--only" {
		inner = inner[2:]
	} else if len(inner) > 0 && strings.HasPrefix(inner[0], "--only=") {
		inner = inner[1:]
	}
	if len(inner) > 0 && inner[0] == "--" {
		inner = inner[1:]
	}
	return inner
}

// exposingBridge recognises the mcp-remote bridge that earlier versions of keyward
// wrote, whose shell expanded each secret into a --header argument, and returns
// the remote server it stands for.
func exposingBridge(s Server) (Server, bool) {
	if s.disabled || !runsThroughKeyward(s) {
		return Server{}, false
	}
	inner := wrappedCommand(s)
	if len(inner) != 3 || inner[0] != "sh" || inner[1] != "-c" {
		return Server{}, false
	}
	script, ok := strings.CutPrefix(inner[2], "exec ")
	if !ok {
		return Server{}, false
	}
	words, ok := splitWords(script)
	if !ok || len(words) < 4 || words[0] != "npx" || words[1] != "-y" || words[2] != "mcp-remote" {
		return Server{}, false
	}
	bridge := Server{Client: s.Client, Config: s.Config, Name: s.Name, Scope: s.Scope, Env: s.Env,
		URL: words[3], Headers: map[string]string{}, toml: s.toml, timeout: s.timeout}
	exposed := false
	for rest := words[4:]; len(rest) > 0; rest = rest[2:] {
		if len(rest) < 2 {
			return Server{}, false
		}
		switch rest[0] {
		case "--transport":
		case "--header":
			name, value, ok := strings.Cut(rest[1], ": ")
			if !ok {
				return Server{}, false
			}
			bridge.Headers[name] = value
			exposed = exposed || placeholder.MatchString(value)
		default:
			return Server{}, false
		}
	}
	return bridge, exposed
}

// splitWords reverses shellWords, turning each $VAR back into ${VAR}. It accepts
// nothing else, so a script written by hand is never mistaken for keyward's.
func splitWords(script string) ([]string, bool) {
	var words []string
	for i := 0; i < len(script); i++ {
		if script[i] != '"' {
			end := strings.IndexByte(script[i:], ' ')
			if end < 0 {
				end = len(script) - i
			}
			if !safeWord.MatchString(script[i : i+end]) {
				return nil, false
			}
			words = append(words, script[i:i+end])
			i += end
		} else {
			var b strings.Builder
			for i < len(script) && script[i] == '"' {
				var ok bool
				if i, ok = unquote(script, i+1, &b); !ok {
					return nil, false
				}
			}
			words = append(words, b.String())
		}
		if i < len(script) && script[i] != ' ' {
			return nil, false
		}
	}
	return words, true
}

// unquote reads one double-quoted segment starting after its opening quote, and
// returns the index after its closing one.
func unquote(script string, i int, b *strings.Builder) (int, bool) {
	for i < len(script) {
		switch c := script[i]; {
		case c == '"':
			return i + 1, true
		case c == '\\' && i+1 < len(script) && strings.IndexByte("\\\"$`", script[i+1]) >= 0:
			b.WriteByte(script[i+1])
			i += 2
		case c == '$':
			n := 0
			for i+1+n < len(script) && isNameChar(script[i+1+n]) {
				n++
			}
			if n == 0 {
				return 0, false
			}
			b.WriteString("${" + script[i+1:i+1+n] + "}")
			i += 1 + n
		case c == '\\' || c == '`':
			return 0, false
		default:
			b.WriteByte(c)
			i++
		}
	}
	return 0, false
}

// shellWords quotes arguments for sh so each placeholder expands there, after
// keyward resolves it. It is written $VAR, without braces, because clients such
// as Claude Code expand ${VAR} themselves before starting the command.
//
// A header for mcp-remote is the exception: it keeps ${VAR} for mcp-remote to
// fill in from its own environment, so the value stays out of every command line,
// which any process can read. It is spelled so neither the client nor sh sees ${.
func shellWords(args []string, headers []int) string {
	words := make([]string, len(args))
	for i, arg := range args {
		if safeWord.MatchString(arg) {
			words[i] = arg
			continue
		}
		var b strings.Builder
		b.WriteByte('"')
		last := 0
		for _, m := range placeholder.FindAllStringSubmatchIndex(arg, -1) {
			b.WriteString(escapeDouble(arg[last:m[0]]))
			if slices.Contains(headers, i) {
				b.WriteString(`"'$''{` + arg[m[2]:m[3]] + `}'"`)
			} else {
				b.WriteString("$" + arg[m[2]:m[3]])
			}
			last = m[1]
			// A name character right after the variable would extend its name.
			if last < len(arg) && isNameChar(arg[last]) {
				b.WriteString(`""`)
			}
		}
		b.WriteString(escapeDouble(arg[last:]))
		b.WriteByte('"')
		words[i] = b.String()
	}
	return strings.Join(words, " ")
}

var safeWord = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func isNameChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func escapeDouble(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(s)
}

func quoteJSON(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func jsonServerText(name, command string, args []string, env map[string]string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env,omitempty"`
	}{command, args, env})
	return quoteJSON(name) + ": " + strings.TrimSuffix(b.String(), "\n")
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func tomlKey(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	return quoteJSON(k)
}

func tomlServer(s Server, command string, args []string, env map[string]string, passEnv []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[mcp_servers.%s]\ncommand = %s\nargs = [\n", tomlKey(s.Name), quoteJSON(command))
	for _, a := range args {
		fmt.Fprintf(&b, "  %s,\n", quoteJSON(a))
	}
	b.WriteString("]\n")
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = tomlKey(k) + " = " + quoteJSON(env[k])
	}
	fmt.Fprintf(&b, "env = { %s }\n", strings.Join(pairs, ", "))
	if len(passEnv) > 0 {
		quoted := make([]string, len(passEnv))
		for i, v := range passEnv {
			quoted[i] = quoteJSON(v)
		}
		fmt.Fprintf(&b, "env_vars = [%s]\n", strings.Join(quoted, ", "))
	}
	if s.timeout != "" {
		fmt.Fprintf(&b, "startup_timeout_sec = %s\n", s.timeout)
	}
	return b.String()
}

func tomlNote(s Server) string {
	note := "Replace the [mcp_servers." + tomlKey(s.Name) + "] table in " + s.Config
	if s.headerTable != "" {
		note += " and delete its " + s.headerTable + " table"
	}
	return note + ". Other subtables, such as tools, can stay."
}
