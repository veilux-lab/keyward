// Package mcpconfig finds MCP servers that read a variable keyward has turned into
// a cap:// reference, and writes the configuration that fixes each one. It also
// finds credentials written into server definitions in plaintext.
//
// It never writes a config file itself. Those files belong to their tools, which
// may rewrite them while running, so Claude Code's servers change through its own
// CLI, and other clients' changes are printed for the user to apply.
package mcpconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
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
	// Project is the folder of the Claude Code project a local or project server
	// is in. Claude Code's CLI changes the server only when run there.
	Project string

	toml     bool
	disabled bool

	// other holds the keys of a Codex table that keyward does not change, as cwd
	// and the tool settings, written again as they are in a table it prints.
	other map[string]any

	// transport is the --transport a bridge gives mcp-remote, if any, kept when it
	// is written again, or sse-only for a server whose type is sse, as keyward's
	// default, http-only, never falls back to SSE.
	transport string

	// subtables name the Codex subtables that hold the server's env and headers.
	// A suggestion replaces them, so its note says to delete them.
	subtables []string

	// httpHeaders are Codex's literal headers, kept out of Headers because Codex
	// fills no variable in them. A suggestion moves their text into env, as it
	// does any header's, to keep it out of mcp-remote's command line.
	httpHeaders map[string]string
}

// Finding is a server that would receive a cap:// reference instead of a value,
// or one that runs through keyward and puts a secret in a command line.
type Finding struct {
	Server
	// Vars are the variables it reads that now hold references, sorted.
	Vars []string
	// Suggestion is the replacement definition, in the client's own format, with
	// literal env and header values hidden, and what may be a secret in its args,
	// or for a server that runs through keyward but whose --only leaves out a
	// reference, or that reads one in its args, the changes to make. It and Want
	// are empty for a server that runs through keyward already, if wrapping it
	// again would change nothing, for one ByHand marks, and for one Arguments
	// returns.
	Suggestion string
	// Note says where the suggestion goes, or why there is none.
	Note string
	// Want is the suggested definition, for applying it rather than printing it.
	Want Definition
	// Exposed names what a server that already runs through keyward puts in a
	// command line, which any process can read: secrets, and headers with text
	// written out that marks a credential.
	Exposed []string
	// InURL names the secrets in a remote server's URL. mcp-remote takes the URL
	// as an argument, so the suggestion puts their values in its command line.
	InURL []string
	// WrittenInURL marks a remote server's URL that may hold a secret written out,
	// in a query string, user info or its path, and goes in that command line too.
	WrittenInURL bool
	// Unresolved names the variables in a server's env whose references its
	// keyward run is not told to resolve, as --only leaves them out, sorted. The
	// server would get each as cap://NAME, not the value.
	Unresolved []string
	// InArgs names the references a server that runs through keyward reads in its
	// command or args, sorted. Its client fills them in there before keyward run
	// starts, which resolves only its environment.
	InArgs []string
	// ByHand marks a server whose script keyward cannot rewrite safely. It has no
	// suggestion, and its note says how to change it by hand.
	ByHand bool
	// Passed names the secrets a server that runs through keyward has its script
	// pass to a program as an argument, so into its command line, sorted. Only the
	// server can take them another way, so there is no suggestion.
	Passed []string
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
	return load(home, workdir, false, nil)
}

func load(home, workdir string, everyProject bool, folders []string) ([]Server, []error) {
	var servers []Server
	var errs []error
	add := func(found []Server, err error) {
		servers = append(servers, found...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	claude, projects, err := loadClaude(filepath.Join(home, ".claude.json"), workdir, everyProject)
	add(claude, err)
	dirs := []string{workdir}
	if everyProject {
		dirs = slices.Concat(dirs, projects, folders)
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		if !seen[dir] {
			seen[dir] = true
			add(loadProject(dir))
		}
	}
	add(loadCodex(filepath.Join(home, ".codex", "config.toml")))
	add(loadJSON("Cursor", filepath.Join(home, ".cursor", "mcp.json"), ""))
	if workdir != home {
		add(loadJSON("Cursor", filepath.Join(workdir, ".cursor", "mcp.json"), ""))
	}
	return servers, errs
}

type jsonServer struct {
	Type    string            `json:"type"`
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
		var transport string
		if s.Type == "sse" {
			transport = "sse-only"
		}
		out = append(out, Server{Client: client, Config: config, Name: name, Scope: scope,
			Command: s.Command, Args: s.Args, Env: s.Env, URL: s.URL, Headers: s.Headers, transport: transport})
	}
	return out
}

// loadClaude reads user-scope servers and the current project's, or with
// everyProject the local servers of every project, and returns the folder of each
// project, sorted.
func loadClaude(path, workdir string, everyProject bool) ([]Server, []string, error) {
	var file struct {
		MCPServers map[string]jsonServer `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]jsonServer `json:"mcpServers"`
		} `json:"projects"`
	}
	if ok, err := readJSON(path, &file); !ok {
		return nil, nil, err
	}
	servers := fromJSON("Claude Code", path, "user", file.MCPServers)
	for dir, p := range file.Projects {
		if everyProject || dir == workdir {
			local := fromJSON("Claude Code", path+" (project "+dir+")", "local", p.MCPServers)
			for i := range local {
				local[i].Project = dir
			}
			servers = append(servers, local...)
		}
	}
	return servers, slices.Sorted(maps.Keys(file.Projects)), nil
}

// loadProject reads the project servers in dir's .mcp.json, which Claude Code's
// CLI changes only when run in dir.
func loadProject(dir string) ([]Server, error) {
	servers, err := loadJSON("Claude Code", filepath.Join(dir, ".mcp.json"), "project")
	for i := range servers {
		servers[i].Project = dir
	}
	return servers, err
}

// Gone reports whether project, the folder of a Claude Code project, no longer
// exists, as a removed worktree's. Claude Code's CLI cannot run there to change
// the project's servers, and Claude Code would not start them.
func Gone(project string) bool {
	if project == "" {
		return false
	}
	info, err := os.Stat(project)
	return errors.Is(err, fs.ErrNotExist) || err == nil && !info.IsDir()
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
		s := Server{Client: "Codex", Config: path, Name: parts[1], toml: true, Env: map[string]string{}, Headers: map[string]string{}, other: maps.Clone(t)}
		for _, read := range []string{"command", "args", "url", "env_vars", "env", "bearer_token_env_var", "env_http_headers", "http_headers"} {
			delete(s.other, read)
		}
		s.Command, _ = t["command"].(string)
		s.Args, _ = t["args"].([]string)
		s.URL, _ = t["url"].(string)
		s.PassEnv, _ = t["env_vars"].([]string)
		s.disabled = t["enabled"] == rawValue("false")
		env, _ := t["env"].(map[string]string)
		if sub := tables[key+"\x00env"]; sub != nil {
			env = stringsOf(sub)
			s.subtables = append(s.subtables, "[mcp_servers."+tomlKey(parts[1])+".env]")
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
			s.subtables = append(s.subtables, "[mcp_servers."+tomlKey(parts[1])+".env_http_headers]")
		}
		for h, v := range headers {
			s.Headers[h] = "${" + v + "}"
		}
		s.httpHeaders, _ = t["http_headers"].(map[string]string)
		if sub := tables[key+"\x00http_headers"]; sub != nil {
			s.httpHeaders = stringsOf(sub)
			s.subtables = append(s.subtables, "[mcp_servers."+tomlKey(parts[1])+".http_headers]")
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

// Check returns the servers that would receive a reference, through keyward run
// or not, and the bridges that run through keyward but put a secret in a command
// line, with any fixes.
func Check(servers []Server, refs map[string]string) []Finding {
	var findings []Finding
	// reported marks the servers found here. Wrapped as suggested, each names in
	// --only every reference in its env.
	reported := make([]bool, len(servers))
	for i, configured := range servers {
		s, expanded, bridged := remoteBridge(configured)
		if !bridged {
			s = configured
		}
		// A server that reads a reference in the command it runs is checked as
		// though it were not wrapped, and wrapped again.
		inArgs := readInArgs(s, refs)
		if len(inArgs) > 0 {
			inner := wrappedCommand(s)
			s.Command, s.Args = inner[0], inner[1:]
		}
		if s.disabled || runsThroughKeyward(s) {
			if f, ok := exposedURL(s, refs); ok {
				findings = append(findings, f)
			}
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
		// sh fills in a variable a script expands, as "$VAR", from the environment
		// the client starts it with, which holds the reference.
		command := append([]string{s.Command}, s.Args...)
		if at, _ := scriptAt(command); at >= 0 && len(inArgs) == 0 {
			words, _ := readScript(command[at])
			for _, w := range words {
				for _, v := range w.expanded {
					if ref, ok := refs[v]; ok {
						used[v] = ref
					}
				}
			}
		}
		for _, v := range s.Headers {
			note(v)
		}
		// Codex sends a ${VAR} in http_headers as written; the bridge fills it in.
		for _, v := range s.httpHeaders {
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
		// mcp-remote started as a command puts its URL in its command line too.
		url := s.URL
		if url == "" {
			url = remoteURL(append([]string{s.Command}, s.Args...))
		}
		f := Finding{Server: s, InURL: secretsIn(url, used), WrittenInURL: writtenInURL(url), InArgs: inArgs}
		if bridged {
			if f.Exposed = commandLine(s, expanded, used); len(f.Exposed) == 0 {
				continue
			}
		}
		for v := range used {
			f.Vars = append(f.Vars, v)
		}
		slices.Sort(f.Vars)
		var ok bool
		if len(inArgs) > 0 {
			f.Suggestion, f.Note, f.Want, ok = rewrap(configured, inArgs, refs, used)
		} else {
			f.Suggestion, f.Note, f.Want, ok = suggest(s, configured, used)
		}
		if !ok {
			f.ByHand, f.InURL, f.WrittenInURL = true, nil, false
		}
		// Only header authentication takes a secret out of the URL, so a bridge that
		// exposes nothing else would be written again as it is.
		if bridged && sameBridge(f.Want, configured) {
			f.Suggestion, f.Want, f.Note = "", Definition{}, unchanged
		}
		findings = append(findings, f)
		reported[i] = true
	}
	for i, s := range servers {
		if f, ok := unresolved(s, refs); ok && !reported[i] {
			findings = append(findings, f)
		}
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		return strings.Compare(a.Client+a.Config+a.Name, b.Client+b.Config+b.Name)
	})
	return findings
}

// readInArgs names the references a server that runs through keyward reads in the
// command it runs, sorted: variables migrated in a shell file, or holding one in
// its env. Its client fills each ${VAR} in before keyward run starts, so keyward
// run, which resolves only its environment, cannot.
func readInArgs(s Server, refs map[string]string) []string {
	if s.disabled || !runsThroughKeyward(s) {
		return nil
	}
	held := handed(s, refs)
	var names []string
	for _, word := range wrappedCommand(s) {
		for _, m := range placeholder.FindAllStringSubmatch(word, -1) {
			if _, ok := refs[m[1]]; ok || slices.Contains(held, m[1]) {
				names = append(names, m[1])
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// rewrap is the fix for a server that runs through keyward but reads a reference
// in the command it runs: that command started as starts starts it, with each
// reference it reads in the server's env, and in its first --only, if it has one,
// with any other reference the server is handed that --only leaves out. It is
// printed as the changes it makes, as unresolved's fix is. It is false for a
// script keyward cannot rewrite safely.
func rewrap(s Server, inArgs []string, refs, used map[string]string) (string, string, Definition, bool) {
	inner := wrappedCommand(s)
	words, shown, ok := starts(inner, used)
	if !ok {
		return "", byHand, Definition{}, false
	}
	want := Definition{Command: s.Command, Args: slices.Concat(s.Args[:len(s.Args)-len(inner)], words)}
	needs := inArgs
	var changes []string
	if only := onlyOf(s.Args); len(only) > 0 {
		var missing []string
		for _, v := range slices.Concat(inArgs, handed(s, refs)) {
			if !slices.Contains(only, v) && !slices.Contains(missing, v) {
				missing = append(missing, v)
			}
		}
		needs = slices.Concat(inArgs, missing)
		if len(missing) > 0 {
			// Sorted, as wrap writes --only, so a bridge it changes reads back as wrap's.
			at := firstOnly(s.Args)
			value := strings.TrimPrefix(s.Args[at], "--only=")
			names := append(strings.Split(value, ","), missing...)
			slices.Sort(names)
			want.Args[at] = strings.TrimSuffix(s.Args[at], value) + strings.Join(names, ",")
			changes = append(changes, "In args, change "+quoteJSON(s.Args[at])+" to "+quoteJSON(want.Args[at])+".")
		}
	}
	// Only the words that change are printed, such as an sh -c script alone.
	same := 0
	for same < len(inner) && same < len(words) && inner[same] == words[same] {
		same++
	}
	before := shownArgs(inner)
	changes = append(changes, "In args, change "+quoteWords(before[same:])+" to "+quoteWords(shown[same:])+".")
	var given []string
	want.Env, given = referenced(s, needs, refs)
	changes = append(changes, given...)
	var fields []string
	if !slices.Equal(before, inner) || !slices.Equal(shown, words) {
		fields = hiddenFields(s)
	}
	return strings.Join(changes, "\n"), changesNote(s, len(changes)) + hiddenNote(nil, nil, fields, false), want, true
}

// unresolved reports a server that runs through keyward with a reference in its
// env that its --only leaves out. The fix is the same server with each such
// variable added to its first --only, printed as the changes it makes, so a
// setting keyward does not read stays as it is.
func unresolved(s Server, refs map[string]string) (Finding, bool) {
	if s.disabled || !runsThroughKeyward(s) {
		return Finding{}, false
	}
	// Without --only, keyward run resolves every reference.
	only := onlyOf(s.Args)
	if len(only) == 0 {
		return Finding{}, false
	}
	f := Finding{Server: s, Vars: handed(s, refs)}
	for _, v := range f.Vars {
		if !slices.Contains(only, v) {
			f.Unresolved = append(f.Unresolved, v)
		}
	}
	if len(f.Unresolved) == 0 {
		return Finding{}, false
	}
	f.Want = Definition{Command: s.Command, Args: slices.Clone(s.Args)}
	at := firstOnly(s.Args)
	f.Want.Args[at] += "," + strings.Join(f.Unresolved, ",")
	changes := []string{"In args, change " + quoteJSON(s.Args[at]) + " to " + quoteJSON(f.Want.Args[at]) + "."}
	var given []string
	f.Want.Env, given = referenced(s, f.Unresolved, refs)
	changes = append(changes, given...)
	f.Suggestion, f.Note = strings.Join(changes, "\n"), changesNote(s, len(changes))
	return f, true
}

// firstOnly is where the args of a keyward run that has an --only give the value
// of the first, as keyward run's first option is one.
func firstOnly(args []string) int {
	if args[1] == "--only" {
		return 2
	}
	return 1
}

// referenced gives each of names that s's env does not set its reference there,
// and returns the env and the changes that make it. keyward run stops on an --only
// name that is not set, and Codex passes an env_vars variable only when it has
// it, so one there moves into env.
func referenced(s Server, names []string, refs map[string]string) (map[string]string, []string) {
	env := maps.Clone(s.Env)
	if env == nil {
		env = map[string]string{}
	}
	var changes, moved []string
	for _, v := range names {
		if _, set := env[v]; set {
			continue
		}
		env[v] = handle.Prefix + refs[v]
		entry := quoteJSON(v) + ": " + quoteJSON(env[v])
		if s.toml {
			entry = tomlKey(v) + " = " + quoteJSON(env[v])
		}
		changes = append(changes, "In env, add "+entry+".")
		if slices.Contains(s.PassEnv, v) {
			moved = append(moved, v)
		}
	}
	for _, v := range moved {
		changes = append(changes, "In env_vars, remove "+quoteJSON(v)+".")
	}
	return env, changes
}

// changesNote says where to make n changes to s, which keep the rest of it.
func changesNote(s Server, n int) string {
	where := "the " + quoteJSON(s.Name) + " entry in " + s.Config
	if s.toml {
		where = "the [mcp_servers." + tomlKey(s.Name) + "] table in " + s.Config
	}
	these := "this change"
	if n > 1 {
		these = "these changes"
	}
	return "Make " + these + " to " + where + ", and leave the rest of it as it is."
}

// handed names the variables that hold a reference in a server's env when it
// starts, sorted: one written there, one its client fills in from a migrated
// variable, and one Codex passes through.
func handed(s Server, refs map[string]string) []string {
	var vars []string
	for k, v := range s.Env {
		// The client fills in a value that is one placeholder; Codex fills none in env.
		if m := placeholder.FindStringSubmatch(v); m != nil && m[0] == v && !s.toml {
			if ref, ok := refs[m[1]]; ok {
				v = handle.Prefix + ref
			}
		}
		if _, err := handle.Parse(v); err == nil {
			vars = append(vars, k)
		}
	}
	for _, v := range s.PassEnv {
		if _, ok := refs[v]; ok {
			vars = append(vars, v)
		}
	}
	slices.Sort(vars)
	return slices.Compact(vars)
}

// suggest wraps the server in keyward run. A remote server goes through the
// mcp-remote bridge, so that its headers are filled in by the local process. Its
// note names fields of current, the definition as written, since a bridge's s is
// the remote server it stands for. It is false, with a note, for a server whose
// script keyward cannot rewrite safely.
func suggest(s, current Server, used map[string]string) (string, string, Definition, bool) {
	env := map[string]string{}
	for k, v := range s.Env {
		env[k] = v
	}
	inner := append([]string{s.Command}, s.Args...)
	var moved []string
	if s.URL != "" {
		inner = []string{"npx", "-y", "mcp-remote", s.URL}
		// Codex's literal headers are sent too, unless a variable sets the same one.
		all := map[string]string{}
		maps.Copy(all, s.httpHeaders)
		maps.Copy(all, s.Headers)
		for _, h := range slices.Sorted(maps.Keys(all)) {
			v := all[h]
			// mcp-remote fills each ${VAR} in a header from its environment, so text
			// written out goes there too, to stay out of its command line.
			var value strings.Builder
			last := 0
			for _, r := range written(v) {
				name := headerVar(env)
				env[name] = v[r[0]:r[1]]
				value.WriteString(v[last:r[0]] + "${" + name + "}")
				last = r[1]
				moved = append(moved, name+" holds text from its "+h+" header")
			}
			inner = append(inner, "--header", h+": "+value.String()+v[last:])
		}
		// A bridge that names no transport is the server's own mcp-remote, as
		// keyward's always name one, and keeps mcp-remote's default.
		transport := s.transport
		if transport == "" && !runsThroughKeyward(current) {
			transport = "http-only"
		}
		if transport != "" {
			inner = append(inner, "--transport", transport)
		}
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
	words, shown, ok := starts(inner, used)
	if !ok {
		return "", byHand, Definition{}, false
	}
	run := []string{"run", "--only", strings.Join(only, ","), "--"}
	printed := slices.Concat(run, shown)
	want := Definition{Command: "keyward", Args: slices.Concat(run, words), Env: env}
	// A bridge's script also holds its header text, which moves to env, so fields
	// are named only if the printed args hide something.
	var fields []string
	if !slices.Equal(printed, want.Args) {
		fields = hiddenFields(current)
	}
	if s.toml {
		// Codex passes on each variable env_vars names but those now in env.
		passEnv := slices.DeleteFunc(slices.Clone(s.PassEnv), func(v string) bool { _, ok := used[v]; return ok })
		table, kept := tomlServer(s, "keyward", printed, env, passEnv)
		return table, tomlNote(s) + hiddenNote(env, moved, fields, kept), want, true
	}
	return jsonServerText(s.Name, "keyward", printed, env), "Replace the " + quoteJSON(s.Name) + " entry in " + s.Config + "." + hiddenNote(env, moved, fields, false), want, true
}

// byHand is the note for a server whose script keyward cannot rewrite safely.
const byHand = `keyward cannot rewrite its script safely, so change it by hand: in the script, write ${VAR} as "$VAR", ` +
	`or as '$''{VAR}' in an mcp-remote --header, for a shell that has VAR in its environment; set VAR to its cap:// reference in env; ` +
	`and start the server with keyward run --only VAR.`

// starts returns the words keyward run starts for inner, and the same as printed.
// A placeholder there that reads a reference must be filled in after keyward run
// resolves it. So a script inner runs is rewritten in place, as another sh -c
// would put each value into the script, and any other command runs through sh,
// which fills each in, but leaves one in a header to mcp-remote, to keep the
// value out of its command line. It is false for a script it cannot rewrite, or
// cannot find.
func starts(inner []string, used map[string]string) (words, printed []string, ok bool) {
	reads := func(w string) bool { return len(secretsIn(w, used)) > 0 }
	at, found := scriptAt(inner)
	if !found && slices.ContainsFunc(inner, reads) {
		return nil, nil, false
	}
	if at >= 0 {
		script, ok := rewriteScript(inner[at], used)
		rest := slices.Delete(slices.Clone(inner), at, at+1)
		if !ok || slices.ContainsFunc(rest, reads) {
			return nil, nil, false
		}
		words = slices.Clone(inner)
		words[at] = script
		return words, shownArgs(words), true
	}
	if !slices.ContainsFunc(inner, placeholder.MatchString) {
		return inner, shownArgs(inner), true
	}
	_, headers := mcpRemote(inner)
	// Each argument is hidden before sh's quoting joins them into one script.
	script := func(args []string) []string { return []string{"sh", "-c", "exec " + shellWords(args, headers)} }
	return script(inner), script(shownArgs(inner)), true
}

// headerVar is the first KW_HDR_n that env does not use.
func headerVar(env map[string]string) string {
	for n := 1; ; n++ {
		name := fmt.Sprintf("KW_HDR_%d", n)
		if _, taken := env[name]; !taken {
			return name
		}
	}
}

// authScheme starts an Authorization header's value, and is no secret.
const authScheme = `(?i:bearer|basic|token) `

var leadingScheme = regexp.MustCompile(`^` + authScheme)

// written returns where a header value is written out, and so may hold a secret:
// everywhere but its placeholders and a leading auth scheme, as [start, end). A
// reference holds none.
func written(v string) [][]int {
	if handle.IsRef(v) {
		return nil
	}
	var found [][]int
	last := len(leadingScheme.FindString(v))
	for _, m := range placeholder.FindAllStringIndex(v, -1) {
		if m[0] > last {
			found = append(found, []int{last, m[0]})
		}
		last = m[1]
	}
	if last < len(v) {
		found = append(found, []int{last, len(v)})
	}
	return found
}

// bare matches a value made only of placeholders without defaults, after any
// auth scheme.
var bare = regexp.MustCompile(`^(?:` + authScheme + `)?(?:\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\})*$`)

// shown is v as printed. Text written out may be a secret, so a value holding
// any, even beside a placeholder, appears only as its length.
func shown(v string) string {
	if handle.IsRef(v) || bare.MatchString(v) {
		return v
	}
	return fmt.Sprintf("<%d bytes hidden>", len(v))
}

// shownArg is an argument as printed, read alone.
func shownArg(arg string) string {
	return shownIn([]string{arg}, 0)
}

// shownArgs is args as printed. One after a --header is printed as a header.
func shownArgs(args []string) []string {
	printed := make([]string, len(args))
	for i := range args {
		printed[i] = shownIn(args, i)
	}
	return printed
}

// shownIn is args[i] as printed. What may be a secret appears only as its length:
// a credential where a value or a word starts, a URL's user info and query
// values, the text of each header it holds, given with --header, and any value
// but a reference or variables after an option named like a credential.
func shownIn(args []string, i int) string {
	arg := args[i]
	var spans [][]int
	for _, c := range credentials(arg, wordStarts) {
		switch word := arg[c.start:c.end]; {
		case strings.Contains(word, "://"):
			// A URL is flagged for its user info, which urlSecrets hides on its own.
		case strings.HasPrefix(word, "-----BEGIN "):
			// A PEM block's key follows its first word.
			spans = append(spans, []int{c.start, len(arg)})
		default:
			// An auth scheme stays, as it does in a header.
			spans = append(spans, []int{c.start + len(leadingScheme.FindString(word)), c.end})
		}
	}
	spans = append(spans, urlSecrets(arg)...)
	for _, h := range headersIn(args, i) {
		spans = append(spans, headerText(h)...)
	}
	for _, o := range optionsIn(args, i) {
		if v := o.String(); v != "" && migrate.NamesCredential(o.name) && !handle.IsRef(v) && !variables.MatchString(v) {
			spans = append(spans, []int{o.at[0], o.end[o.Len()-1]})
		}
	}
	slices.SortFunc(spans, func(a, b []int) int { return a[0] - b[0] })
	var b strings.Builder
	last := 0
	for j := 0; j < len(spans); {
		// A secret can be found more than once, so spans may overlap.
		start, end := spans[j][0], spans[j][1]
		for j++; j < len(spans) && spans[j][0] <= end; j++ {
			end = max(end, spans[j][1])
		}
		fmt.Fprintf(&b, "%s<%d bytes hidden>", arg[last:start], end-start)
		last = end
	}
	return b.String() + arg[last:]
}

// wordStarts adds the start of each word to valueStarts, so that each argument in
// a script is read as if it stood alone. Printing can hide more than doctor
// reports: a value hidden by mistake only has to be copied.
func wordStarts(before string) bool {
	return valueStarts(before) || strings.HasSuffix(before, " ")
}

// variables matches a value made only of variables without defaults, as a
// client or, in a script, sh fills them in.
var variables = regexp.MustCompile(`^(?:\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)+$`)

// urlSecrets returns where each URL in arg has user info or a query value that
// is written out, and so may be a secret, as [start, end). A token can be the
// user name as well as the password.
func urlSecrets(arg string) [][]int {
	var found [][]int
	add := func(start int, part string) {
		if part != "" && !variables.MatchString(part) {
			found = append(found, []int{start, start + len(part)})
		}
	}
	for from := 0; ; {
		i := strings.Index(arg[from:], "://")
		if i < 0 {
			return found
		}
		start, end := from+i+len("://"), len(arg)
		if n := strings.IndexAny(arg[start:], wordEnds); n >= 0 {
			end = start + n
		}
		url := arg[start:end]
		// User info ends at the last @ before a query, as a URL parser reads it, or
		// at the first @ before the path, as Detect does, so a password can hold an
		// @ or a ?. What either calls user info is hidden.
		authority, _, _ := strings.Cut(url, "/")
		beforeQuery, _, _ := strings.Cut(authority, "?")
		for _, at := range []int{strings.LastIndexByte(beforeQuery, '@'), strings.IndexByte(authority, '@')} {
			if at >= 0 {
				user, password, _ := strings.Cut(url[:at], ":")
				add(start, user)
				add(start+at-len(password), password)
			}
		}
		if _, query, ok := strings.Cut(url, "?"); ok {
			offset := end - len(query)
			for _, param := range strings.Split(query, "&") {
				_, value, ok := strings.Cut(param, "=")
				if !ok {
					value = param
				}
				add(offset+len(param)-len(value), value)
				offset += len(param) + 1
			}
		}
		// What is read as one URL can hold more: a list, or one inside another.
		from = start
	}
}

// hiddenNote says where the values a printed definition hides come from: moved
// says which header each new KW_HDR variable holds text from, and fields name
// those of the current definition with text the printed args hide. kept reports
// whether it hides text of a key it keeps, which the same key holds.
func hiddenNote(env map[string]string, moved, fields []string, kept bool) string {
	if !kept && len(fields) == 0 && !slices.ContainsFunc(slices.Collect(maps.Values(env)), func(v string) bool { return shown(v) != v }) {
		return ""
	}
	notes := append([]string{"Copy each hidden value from the current definition"}, moved...)
	if len(fields) > 0 {
		notes = append(notes, "the hidden text in args is from its "+strings.Join(fields, ", "))
	}
	return " " + strings.Join(notes, "; ") + "."
}

// hiddenFields names each field of s with text shownArg hides. Its command is an
// argument too once keyward run starts it.
func hiddenFields(s Server) []string {
	var fields []string
	if shownArg(s.Command) != s.Command {
		fields = append(fields, "command")
	}
	if shownArg(s.URL) != s.URL {
		fields = append(fields, "url")
	}
	for i, a := range shownArgs(s.Args) {
		if a != s.Args[i] {
			fields = append(fields, fmt.Sprintf("args[%d]", i))
		}
	}
	return fields
}

// secretsIn names the variables in used that text reads, sorted.
func secretsIn(text string, used map[string]string) []string {
	var names []string
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		if _, ok := used[m[1]]; ok {
			names = append(names, m[1])
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// writtenInURL reports whether a URL may hold a secret written out: it has a query
// string or user info, or a credential doctor reports, as in a segment of its path.
func writtenInURL(url string) bool {
	_, rest, _ := strings.Cut(url, "://")
	authority, _, _ := strings.Cut(rest, "/")
	d := argument(url)
	return strings.Contains(url, "?") || strings.Contains(authority, "@") || d.Secret || d.Possible
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
		printed := shownArgs(inner)
		if s.toml {
			// Codex fills no variable in env, so it passes each reference's on.
			passEnv := slices.Clone(s.PassEnv)
			for _, v := range f.Vars {
				if !slices.Contains(passEnv, v) {
					passEnv = append(passEnv, v)
				}
			}
			var kept bool
			f.Suggestion, kept = tomlServer(s, printed[0], printed[1:], env, passEnv)
			f.Note = tomlNote(s) + hiddenNote(env, nil, hiddenFields(s), kept)
		} else {
			f.Suggestion = jsonServerText(s.Name, printed[0], printed[1:], env)
			f.Note = "Replace the " + quoteJSON(s.Name) + " entry in " + s.Config + "." + hiddenNote(env, nil, hiddenFields(s), false)
		}
		findings = append(findings, f)
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		return strings.Compare(a.Client+a.Config+a.Name, b.Client+b.Config+b.Name)
	})
	return findings
}

// wrappedCommand is the command a keyward-wrapped server starts, after keyward
// run and each of its options, read as keyward run reads them.
func wrappedCommand(s Server) []string {
	inner := s.Args[1:]
	for len(inner) > 0 {
		if strings.HasPrefix(inner[0], "--only=") {
			inner = inner[1:]
		} else if inner[0] == "--only" && len(inner) > 1 {
			inner = inner[2:]
		} else {
			break
		}
	}
	if len(inner) > 0 && inner[0] == "--" {
		inner = inner[1:]
	}
	return inner
}

// onlyOf is the names a keyward run's --only options list, read from its args as
// keyward run reads them, or none if it has no --only.
func onlyOf(args []string) []string {
	var names []string
	for args = args[1:]; len(args) > 0; args = args[1:] {
		value, inline := strings.CutPrefix(args[0], "--only=")
		if !inline {
			if args[0] != "--only" || len(args) < 2 {
				break
			}
			value, args = args[1], args[1:]
		}
		names = append(names, strings.Split(value, ",")...)
	}
	return names
}

// remoteBridge is bridgeOf for a bridge Check writes again, one that is on and
// runs through keyward.
func remoteBridge(s Server) (Server, []string, bool) {
	if s.disabled || !runsThroughKeyward(s) {
		return Server{}, nil, false
	}
	return bridgeOf(s)
}

// bridgeOf recognises the mcp-remote bridge keyward writes, in the current
// spelling or an earlier one, with or without the keyward run that unwrap takes
// away, and returns the remote server it stands for and the variables its shell
// expands into mcp-remote's arguments.
func bridgeOf(s Server) (Server, []string, bool) {
	inner := append([]string{s.Command}, s.Args...)
	if runsThroughKeyward(s) {
		inner = wrappedCommand(s)
	}
	if len(inner) != 3 || inner[0] != "sh" || inner[1] != "-c" {
		return Server{}, nil, false
	}
	url, headers, transport, expanded, ok := readBridge(inner[2])
	if !ok {
		return Server{}, nil, false
	}
	bridge := Server{Client: s.Client, Config: s.Config, Name: s.Name, Scope: s.Scope, Project: s.Project, Env: s.Env, PassEnv: s.PassEnv,
		URL: url, Headers: map[string]string{}, toml: s.toml, other: s.other, subtables: s.subtables, transport: transport}
	for _, h := range headers {
		name, value, _ := strings.Cut(h.String(), ": ")
		bridge.Headers[name] = value
	}
	return bridge, expanded, true
}

// sameBridge reports whether want starts the bridge that configured does, with the
// same --only, env, URL, headers and transport, and sh expanding the same
// variables, in whatever order its words are.
func sameBridge(want Definition, configured Server) bool {
	a, aExpanded, aOK := bridgeOf(Server{Command: want.Command, Args: want.Args})
	b, bExpanded, bOK := bridgeOf(configured)
	sorted := func(names []string) []string { return slices.Sorted(slices.Values(names)) }
	return aOK && bOK && maps.Equal(want.Env, configured.Env) && slices.Equal(sorted(onlyOf(want.Args)), sorted(onlyOf(configured.Args))) &&
		a.URL == b.URL && maps.Equal(a.Headers, b.Headers) && a.transport == b.transport && slices.Equal(sorted(aExpanded), sorted(bExpanded))
}

// readBridge reads a bridge's script: the remote server's URL, each header sent to
// it, as NAME: value, the transport it names, and the variables sh expands into
// mcp-remote's arguments. The URL is the first word that is not a header, as
// mcp-remote reads it.
func readBridge(script string) (url string, headers []*scriptWord, transport string, expanded []string, ok bool) {
	if !strings.HasPrefix(script, "exec npx -y mcp-remote ") {
		return "", nil, "", nil, false
	}
	words, expanded, ok := splitWords(script)
	if !ok {
		return "", nil, "", nil, false
	}
	found := false
	for rest := words[4:]; len(rest) > 0; {
		switch option := rest[0].String(); {
		case option == "--header" && len(rest) > 1:
			if !strings.Contains(rest[1].String(), ": ") {
				return "", nil, "", nil, false
			}
			headers, rest = append(headers, rest[1]), rest[2:]
		case !found:
			url, found, rest = option, true, rest[1:]
		case option == "--transport" && len(rest) > 1:
			transport, rest = rest[1].String(), rest[2:]
		default:
			return "", nil, "", nil, false
		}
	}
	return url, headers, transport, expanded, found
}

// cutHeader splits a header given as Name: value or Name:value, as mcp-remote
// reads one.
func cutHeader(h string) (name, value string, ok bool) {
	name, value, ok = strings.Cut(h, ":")
	if !ok || !headerName.MatchString(name) {
		return "", "", false
	}
	return name, strings.TrimLeft(value, " \t"), true
}

// headerName is a header's name as mcp-remote accepts it.
var headerName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// headersIn returns each header args[i] holds, given with --header: args[i] after
// a --header, the rest of a --header= in it, and each such word of a script it
// is, a bridge's included. Each says where args[i] writes its bytes.
func headersIn(args []string, i int) []*scriptWord {
	arg := args[i]
	switch {
	case i > 0 && args[i-1] == "--header":
		return []*scriptWord{wordOf(arg)}
	case strings.HasPrefix(arg, "--header="):
		return []*scriptWord{wordOf(arg).from(len("--header="))}
	}
	words := scriptWords(args, i)
	var found []*scriptWord
	for j, w := range words {
		if j > 0 && words[j-1].String() == "--header" {
			found = append(found, w)
		} else if strings.HasPrefix(w.String(), "--header=") {
			found = append(found, w.from(len("--header=")))
		}
	}
	return found
}

// optionValue is a value given with an option, as in --api-key VALUE or
// --api-key=VALUE, with the option's name as a variable's, as in API_KEY.
type optionValue struct {
	name string
	*scriptWord
}

// detect judges an option's value by the option's name, as a header's value is
// judged by the header's. Only a name that marks a credential counts: a package
// named after -y can look as random as a key.
func (o optionValue) detect() migrate.Detection {
	if d := migrate.Detect(o.name, o.String()); d.Secret {
		return d
	}
	return migrate.Detection{}
}

// optionName is an option's name, after its dashes, as a command line gives one.
var optionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// optionsIn returns each value args[i] holds that follows an option: args[i] after
// one, the rest of an --option= in it, and each such word of a script it is. Each
// says where args[i] writes its bytes. --header gives a header, which headersIn
// finds.
func optionsIn(args []string, i int) []optionValue {
	var found []optionValue
	add := func(opt string, w *scriptWord) {
		name := strings.TrimLeft(opt, "-")
		if name != opt && opt != "--header" && optionName.MatchString(name) && !strings.HasPrefix(w.String(), "-") {
			found = append(found, optionValue{strings.ToUpper(strings.ReplaceAll(name, "-", "_")), w})
		}
	}
	inline := func(w *scriptWord) {
		if opt, _, ok := strings.Cut(w.String(), "="); ok {
			add(opt, w.from(len(opt)+1))
		}
	}
	if i > 0 {
		add(args[i-1], wordOf(args[i]))
	}
	inline(wordOf(args[i]))
	words := scriptWords(args, i)
	for j, w := range words {
		if j > 0 {
			add(words[j-1].String(), w)
		}
		inline(w)
	}
	return found
}

// scriptWords returns the words of args[i] if it is a script: one in keyward's
// spelling, read as splitWords reads it, or any a shell is given with -c, read as
// sh reads it. Each says where args[i] writes its bytes.
func scriptWords(args []string, i int) []*scriptWord {
	if strings.HasPrefix(args[i], "exec ") {
		if words, _, ok := splitWords(args[i]); ok {
			return words
		}
	} else if i == 0 || !scriptOption.MatchString(args[i-1]) {
		return nil
	}
	read, _ := readScript(args[i])
	words := make([]*scriptWord, len(read))
	for j, w := range read {
		words[j] = w.scriptWord
	}
	return words
}

// headerText returns where the header h is written out in the argument that holds
// it, as [start, end): all but its name, auth scheme and placeholders. Only its
// name may mark its text as a credential.
func headerText(h *scriptWord) [][]int {
	_, value, ok := cutHeader(h.String())
	if !ok {
		return nil
	}
	from := h.Len() - len(value)
	var found [][]int
	for _, r := range written(value) {
		found = append(found, []int{h.at[from+r[0]], h.end[from+r[1]-1]})
	}
	return found
}

// exposedURL reports a server that runs through keyward with a script not read as
// a bridge, as one that gives mcp-remote a callback port, whose sh expands a
// secret into the URL it gives mcp-remote, and so into its command line. Only
// header authentication would take the secret out.
func exposedURL(s Server, refs map[string]string) (Finding, bool) {
	words, ok := wrappedScript(s)
	url, _ := remoteWords(words)
	if !ok || url < 0 {
		return Finding{}, false
	}
	exposed := resolved(s, refs, words[url].expanded)
	return Finding{Server: s, Vars: exposed, Exposed: exposed, InURL: exposed, WrittenInURL: true, Note: unchanged}, len(exposed) > 0
}

// Arguments returns each server that runs through keyward whose script passes a
// secret to a program as an argument, so into its command line, with Passed
// naming them. Only the server can take one another way, so none has a change.
// A bridge keyward reads is left to Check, which writes it again.
func Arguments(servers []Server, refs map[string]string) []Finding {
	var found []Finding
	for _, s := range servers {
		if _, _, bridged := remoteBridge(s); bridged {
			continue
		}
		if passed := passedAsArgument(s, refs); len(passed) > 0 {
			found = append(found, Finding{Server: s, Vars: passed, Passed: passed})
		}
	}
	slices.SortFunc(found, func(a, b Finding) int {
		return strings.Compare(a.Client+a.Config+a.Name, b.Client+b.Config+b.Name)
	})
	return found
}

// passedAsArgument names the secrets that the script of a server that runs
// through keyward passes to a program as an argument, but in mcp-remote's URL,
// which Check reports, sorted. A variable set for a command, and one a shell
// builtin reads, as printf piping it to a program, are in no command line.
func passedAsArgument(s Server, refs map[string]string) []string {
	words, ok := wrappedScript(s)
	if !ok {
		return nil
	}
	url, _ := remoteWords(words)
	var passed []string
	eachCommand(words, func(start int, texts []string) {
		// exec runs a program even of a builtin's name.
		program := launched(texts)
		if program < 0 || slices.Contains(builtins, texts[program]) && !slices.Contains(texts[:program], "exec") {
			return
		}
		for i := start + program + 1; i < start+len(texts); i++ {
			if i != url {
				passed = append(passed, words[i].expanded...)
			}
		}
	})
	return resolved(s, refs, passed)
}

// builtins are commands a shell runs itself, which put what they read in no
// program's command line.
var builtins = []string{"echo", "printf", "export", "local", "readonly", "declare", "typeset", "read", "test", "[", "cd", ":"}

// wrappedScript reads the script of a server that runs through keyward, if the
// command it starts is a shell given one, that keyward can read.
func wrappedScript(s Server) ([]shellWord, bool) {
	if s.disabled || !runsThroughKeyward(s) {
		return nil, false
	}
	inner := wrappedCommand(s)
	at, _ := scriptAt(inner)
	if at < 0 {
		return nil, false
	}
	return readScript(inner[at])
}

// resolved returns those of vars that keyward run resolves to a secret for s,
// sorted: each migrated in a shell file, and each holding a reference in its env.
func resolved(s Server, refs map[string]string, vars []string) []string {
	held := handed(s, refs)
	var found []string
	for _, v := range vars {
		if _, ok := refs[v]; ok || slices.Contains(held, v) {
			found = append(found, v)
		}
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// unchanged is the note for a server that already runs through keyward, whose URL
// alone puts a secret in a command line.
const unchanged = "It already runs through keyward, so wrapping it again would change nothing."

// commandLine names the secrets a bridge puts in mcp-remote's arguments: each its
// shell expands, and each header whose text written out the header's name or
// value marks as a credential, as doctor judges a header. An ordinary header, as
// Accept is, holds none.
func commandLine(bridge Server, expanded []string, used map[string]string) []string {
	var found []string
	for _, v := range expanded {
		if _, ok := used[v]; ok {
			found = append(found, v)
		}
	}
	slices.Sort(found)
	found = slices.Compact(found)
	for _, h := range slices.Sorted(maps.Keys(bridge.Headers)) {
		v := bridge.Headers[h]
		if len(written(v)) > 0 && header(h, placeholder.ReplaceAllString(v, "")).Secret {
			found = append(found, "the "+h+" header")
		}
	}
	return found
}

// splitWords reverses shellWords, turning each placeholder back into ${VAR}, and
// names the variables sh expands. It accepts nothing else, so a script written by
// hand is never mistaken for keyward's.
func splitWords(script string) (words []*scriptWord, expanded []string, ok bool) {
	for i := 0; i < len(script); i++ {
		w := new(scriptWord)
		if script[i] != '"' {
			end := strings.IndexByte(script[i:], ' ')
			if end < 0 {
				end = len(script) - i
			}
			if !safeWord.MatchString(script[i : i+end]) {
				return nil, nil, false
			}
			for j := i; j < i+end; j++ {
				w.add(script[j], j, j+1)
			}
			i += end
		} else {
			for i < len(script) {
				if script[i] == '"' {
					if i, ok = unquote(script, i+1, w, &expanded); !ok {
						return nil, nil, false
					}
				} else if m := leftForMCPRemote.FindStringSubmatch(script[i:]); m != nil {
					w.variable(m[1], i, i+len(m[0]))
					i += len(m[0])
				} else {
					break
				}
			}
		}
		words = append(words, w)
		if i < len(script) && script[i] != ' ' {
			return nil, nil, false
		}
	}
	return words, expanded, true
}

// scriptWord is a word of a script as sh reads it, with where the script writes
// each of its bytes, as [at, end), so that text in it can be hidden there. An
// escaped byte is written as two, and each byte of a variable where the whole
// variable is.
type scriptWord struct {
	strings.Builder
	at, end []int
}

// add appends c, which the script writes in [at, end).
func (w *scriptWord) add(c byte, at, end int) {
	w.WriteByte(c)
	w.at = append(w.at, at)
	w.end = append(w.end, end)
}

// variable appends ${name}, for a variable the script writes in [at, end).
func (w *scriptWord) variable(name string, at, end int) {
	for _, c := range []byte("${" + name + "}") {
		w.add(c, at, end)
	}
}

// wordOf is arg as one word, each byte written where it is.
func wordOf(arg string) *scriptWord {
	w := new(scriptWord)
	for i := range len(arg) {
		w.add(arg[i], i, i+1)
	}
	return w
}

// from is w without its first n bytes.
func (w *scriptWord) from(n int) *scriptWord {
	rest := &scriptWord{at: w.at[n:], end: w.end[n:]}
	rest.WriteString(w.String()[n:])
	return rest
}

// leftForMCPRemote is a header's ${VAR} as shellWords writes it.
var leftForMCPRemote = regexp.MustCompile(`^'\$''\{([A-Za-z_][A-Za-z0-9_]*)\}'`)

// unquote reads one double-quoted segment starting after its opening quote, and
// returns the index after its closing one. It adds each $VAR to expanded.
func unquote(script string, i int, w *scriptWord, expanded *[]string) (int, bool) {
	for i < len(script) {
		switch c := script[i]; {
		case c == '"':
			return i + 1, true
		case c == '\\' && i+1 < len(script) && strings.IndexByte("\\\"$`", script[i+1]) >= 0:
			w.add(script[i+1], i, i+2)
			i += 2
		case c == '$':
			n := 0
			for i+1+n < len(script) && isNameChar(script[i+1+n]) {
				n++
			}
			if n == 0 {
				return 0, false
			}
			*expanded = append(*expanded, script[i+1:i+1+n])
			w.variable(script[i+1:i+1+n], i, i+1+n)
			i += 1 + n
		case c == '\\' || c == '`':
			return 0, false
		default:
			w.add(c, i, i+1)
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

// shells are the programs that run a script given with -c.
var shells = []string{"sh", "bash", "dash", "zsh", "ksh"}

// scriptOption is a shell's options that include -c, as in -c or -lc.
var scriptOption = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

// shellOptions are a shell's options that take an argument.
var shellOptions = []string{"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}

// scriptAt returns where inner holds the script that the shell it runs is given
// with -c, as in sh -c SCRIPT, bash -lc SCRIPT or env A=1 bash -O extglob -c
// SCRIPT, or -1. It is false for a shell given -c that it cannot be sure of: one
// that another program starts, as env -i or docker run does, in an environment
// that may lack a variable the script reads, or one given an option it does not
// know, which may take an argument, so that it cannot tell which is the script.
func scriptAt(inner []string) (int, bool) {
	program := launched(inner)
	for i, word := range inner {
		if !slices.Contains(shells, filepath.Base(word)) {
			continue
		}
		j := i + 1
		for ; j+1 < len(inner) && (strings.HasPrefix(inner[j], "-") || strings.HasPrefix(inner[j], "+")); j++ {
			switch {
			case scriptOption.MatchString(inner[j]) && i == program:
				return j + 1, true
			case scriptOption.MatchString(inner[j]):
				return -1, false
			case slices.Contains(shellOptions, inner[j]):
				j++ // its argument
			}
		}
		if slices.ContainsFunc(inner[j:], scriptOption.MatchString) {
			return -1, false
		}
	}
	return -1, true
}

// assignment is a word that sets a variable, as env and a script's command take.
var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// launched returns where words name the program they run, past the launchers that
// keep its environment: exec and assignments before a script's command, env given
// only assignments, nohup, and nice. It is -1 for env given an option, as -i or
// -u, which leaves variables out.
func launched(words []string) int {
	for i := 0; i < len(words); {
		switch name := filepath.Base(words[i]); {
		case words[i] == "exec" || name == "nohup" || assignment.MatchString(words[i]):
			i++
		case name == "env":
			for i++; i < len(words) && assignment.MatchString(words[i]); i++ {
			}
			if i < len(words) && strings.HasPrefix(words[i], "-") {
				return -1
			}
		case name == "nice":
			i++
			if i+1 < len(words) && words[i] == "-n" {
				i += 2
			} else if i < len(words) && niceIncrement.MatchString(words[i]) {
				i++
			}
		default:
			return i
		}
	}
	return -1
}

// niceIncrement is nice's increment given the old way, as in nice -10.
var niceIncrement = regexp.MustCompile(`^-[0-9]+$`)

// mcpRemote returns where words that start mcp-remote give it the server's URL,
// and each header to send, each word after a --header. As mcp-remote reads them,
// the URL is the first word after its name that is neither a --header or
// --header-file nor the value after one. url is -1 if words do not start it.
func mcpRemote(words []string) (url int, headers []int) {
	at := slices.IndexFunc(words, func(w string) bool {
		name := filepath.Base(w)
		return !strings.Contains(w, "://") && (name == "mcp-remote" || strings.HasPrefix(name, "mcp-remote@"))
	})
	if at < 0 {
		return -1, nil
	}
	url = -1
	for i := at + 1; i < len(words); i++ {
		switch {
		case (words[i] == "--header" || words[i] == "--header-file") && i+1 < len(words):
			if words[i] == "--header" {
				headers = append(headers, i+1)
			}
			i++
		case url < 0:
			url = i
		}
	}
	return url, headers
}

// remoteURL is the URL that inner gives mcp-remote, as an argument or in a script
// it runs, as written, or "" if it starts no mcp-remote that keyward can read.
func remoteURL(inner []string) string {
	if at, _ := scriptAt(inner); at >= 0 {
		words, _ := readScript(inner[at])
		if url, _ := remoteWords(words); url >= 0 {
			return words[url].String()
		}
		return ""
	}
	if url, _ := mcpRemote(inner); url >= 0 {
		return inner[url]
	}
	return ""
}

// shellWord is a word of a script as sh reads it, but with each placeholder and
// variable in it as written, as the client fills placeholders in first, and with
// where the script writes each of its bytes. command counts the commands of the
// script before it, and expanded names each variable sh expands in it.
type shellWord struct {
	*scriptWord
	command      int
	placeholders []filled
	expanded     []string
}

// filled is a placeholder in a script: where it is, the variable it reads, and the
// quote it is in, if any.
type filled struct {
	start, end int
	name       string
	quote      byte
}

// readScript reads a script as sh does, into its words. It accepts only words,
// quotes, escapes, $VAR and the operators between commands, so that it knows how
// sh reads each placeholder, and is false for anything else, such as $(...).
func readScript(script string) ([]shellWord, bool) {
	found := placeholder.FindAllStringSubmatchIndex(script, -1)
	var words []shellWord
	var quote byte
	inWord, command := false, 0
	// word is the word being read, started if need be.
	word := func() *shellWord {
		if !inWord {
			words = append(words, shellWord{scriptWord: new(scriptWord), command: command})
			inWord = true
		}
		return &words[len(words)-1]
	}
	// add appends script[from:to] to the word, each byte where it is written.
	add := func(from, to int) *shellWord {
		w := word()
		for j := from; j < to; j++ {
			w.add(script[j], j, j+1)
		}
		return w
	}
	for i := 0; i < len(script); {
		if len(found) > 0 && found[0][0] == i {
			m := found[0]
			found = found[1:]
			w := add(m[0], m[1])
			w.placeholders = append(w.placeholders, filled{m[0], m[1], script[m[2]:m[3]], quote})
			i = m[1]
			continue
		}
		c, n := script[i], 1
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				add(i, i+1)
			}
		case c == '\\':
			if i+1 == len(script) || script[i+1] == '\n' {
				return nil, false
			}
			// Between double quotes, a backslash escapes only these, and is kept
			// before anything else.
			if quote == 0 || strings.IndexByte("\\\"$`", script[i+1]) >= 0 {
				n = 2
			}
			word().add(script[i+n-1], i, i+n)
		case c == '`':
			return nil, false
		case c == '$':
			if n = expansion(script[i:], quote == '"'); n == 0 {
				return nil, false
			}
			w := add(i, i+n)
			if n > 1 && isNameChar(script[i+1]) && (script[i+1] < '0' || script[i+1] > '9') {
				w.expanded = append(w.expanded, script[i+1:i+n])
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				add(i, i+1)
			}
		case c == '"' || c == '\'':
			quote = c
			word()
		case c == ' ' || c == '\t':
			inWord = false
		case c == '#' && !inWord, strings.HasPrefix(script[i:], "<<"):
			// A comment and a here-document are read another way.
			return nil, false
		case strings.IndexByte("\n;&|()<>", c) >= 0:
			inWord = false
			if c != '<' && c != '>' {
				command++
			}
		default:
			add(i, i+1)
		}
		// A placeholder inside what sh reads as one, as in \${VAR}, cannot be rewritten.
		if len(found) > 0 && found[0][0] < i+n {
			return nil, false
		}
		i += n
	}
	return words, quote == 0
}

// expansion is the length of what sh expands at the start of s, which starts with
// $: a variable or a special parameter, or 1 for a $ it reads as itself. It is 0
// for one whose quoting keyward does not read, such as ${VAR%x} or $(...).
func expansion(s string, quoted bool) int {
	switch {
	case len(s) == 1:
		return 1
	case s[1] == '{' || s[1] == '(' || !quoted && (s[1] == '\'' || s[1] == '"'):
		return 0
	case strings.IndexByte("@*#?-$!0123456789", s[1]) >= 0:
		return 2
	case s[1] == '_' || s[1] >= 'a' && s[1] <= 'z' || s[1] >= 'A' && s[1] <= 'Z':
		n := 2
		for n < len(s) && isNameChar(s[n]) {
			n++
		}
		return n
	}
	return 1
}

// eachCommand calls f with each command of a script's words, read apart: where it
// starts, and the text of each of its words.
func eachCommand(words []shellWord, f func(start int, texts []string)) {
	for start := 0; start < len(words); {
		end := start + 1
		for end < len(words) && words[end].command == words[start].command {
			end++
		}
		texts := make([]string, 0, end-start)
		for _, w := range words[start:end] {
			texts = append(texts, w.String())
		}
		f(start, texts)
		start = end
	}
}

// remoteWords returns which word of a script gives mcp-remote its URL, or -1, and
// which give it a header.
func remoteWords(words []shellWord) (url int, headers []bool) {
	url, headers = -1, make([]bool, len(words))
	eachCommand(words, func(start int, texts []string) {
		at, marked := mcpRemote(texts)
		if at >= 0 && url < 0 {
			url = start + at
		}
		for _, h := range marked {
			headers[start+h] = true
		}
	})
	return url, headers
}

// nestedScripts marks each word of a script that is another shell's script, and
// each word of a command that runs a shell whose script scriptAt cannot find.
func nestedScripts(words []shellWord) []bool {
	marked := make([]bool, len(words))
	eachCommand(words, func(start int, texts []string) {
		switch at, found := scriptAt(texts); {
		case !found:
			for i := range texts {
				marked[start+i] = true
			}
		case at >= 0:
			marked[start+at] = true
		}
	})
	return marked
}

// rewriteScript rewrites each placeholder in script that reads a variable in used,
// so that it is filled in after keyward run resolves it: by sh, as "$VAR", or in a
// header mcp-remote is given, by mcp-remote, spelled as shellWords spells one. It
// is false if one is in a script that readScript cannot read, or where sh could
// pass the value on to a command line unseen: in another shell's script, or in a
// script that runs mcp-remote, anywhere but its URL and headers.
func rewriteScript(script string, used map[string]string) (string, bool) {
	if len(secretsIn(script, used)) == 0 {
		return script, true
	}
	words, ok := readScript(script)
	if !ok {
		return "", false
	}
	url, headers := remoteWords(words)
	nested := nestedScripts(words)
	var b strings.Builder
	last := 0
	for i, w := range words {
		for _, p := range w.placeholders {
			if _, ok := used[p.name]; !ok {
				continue
			}
			if nested[i] || url >= 0 && i != url && !headers[i] {
				return "", false
			}
			b.WriteString(script[last:p.start])
			last = p.end
			// Each spelling ends the quote it is in and opens it again.
			switch {
			case headers[i] && p.quote == '"':
				b.WriteString(`"'$''{` + p.name + `}'"`)
			case headers[i] && p.quote == '\'':
				b.WriteString(`$''{` + p.name + `}`)
			case headers[i]:
				b.WriteString(`'$''{` + p.name + `}'`)
			case p.quote == '"':
				b.WriteString("$" + p.name)
				// A name character right after the variable would extend its name.
				if last < len(script) && isNameChar(script[last]) {
					b.WriteString(`""`)
				}
			case p.quote == '\'':
				b.WriteString(`'"$` + p.name + `"'`)
			default:
				b.WriteString(`"$` + p.name + `"`)
			}
		}
	}
	return b.String() + script[last:], true
}

func quoteJSON(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func jsonServerText(name, command string, args []string, env map[string]string) string {
	printed := map[string]string{}
	for k, v := range env {
		printed[k] = shown(v)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env,omitempty"`
	}{command, args, printed})
	return quoteJSON(name) + ": " + strings.TrimSuffix(b.String(), "\n")
}

// quoteWords is words as a JSON or TOML array lists them.
func quoteWords(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = quoteJSON(w)
	}
	return strings.Join(quoted, ", ")
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func tomlKey(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	return quoteJSON(k)
}

// tomlServer is the Codex table for s that starts command with args, env and the
// variables passEnv names, with each other key of s as it is. It reports whether
// it hides text of one of those keys.
func tomlServer(s Server, command string, args []string, env map[string]string, passEnv []string) (string, bool) {
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
		pairs[i] = tomlKey(k) + " = " + quoteJSON(shown(env[k]))
	}
	fmt.Fprintf(&b, "env = { %s }\n", strings.Join(pairs, ", "))
	if len(passEnv) > 0 {
		fmt.Fprintf(&b, "env_vars = [%s]\n", quoteWords(passEnv))
	}
	hides := false
	for _, k := range slices.Sorted(maps.Keys(s.other)) {
		value := tomlValue(s.other[k], true)
		hides = hides || value != tomlValue(s.other[k], false)
		fmt.Fprintf(&b, "%s = %s\n", tomlKey(k), value)
	}
	return b.String(), hides
}

// tomlValue writes v, as readTOML read it, as TOML, with what may be a secret
// hidden if hide is set: Codex reads none in the keys it is for, but a key it
// does not read, as a header written as Claude Code writes one, can hold one.
func tomlValue(v any, hide bool) string {
	arg, literal := func(s string) string { return s }, func(s string) string { return s }
	if hide {
		arg, literal = shownArg, shown
	}
	switch v := v.(type) {
	case string:
		return quoteJSON(arg(v))
	case []string:
		items := make([]string, len(v))
		for i, item := range v {
			items[i] = arg(item)
		}
		return "[" + quoteWords(items) + "]"
	case map[string]string:
		var pairs []string
		for _, k := range slices.Sorted(maps.Keys(v)) {
			pairs = append(pairs, tomlKey(k)+" = "+quoteJSON(literal(v[k])))
		}
		return "{ " + strings.Join(pairs, ", ") + " }"
	}
	return arg(string(v.(rawValue)))
}

func tomlNote(s Server) string {
	note := "Replace the [mcp_servers." + tomlKey(s.Name) + "] table in " + s.Config
	if len(s.subtables) > 0 {
		note += " and delete its " + strings.Join(s.subtables, " table and its ") + " table"
	}
	return note + ". Other subtables, such as tools, can stay."
}
