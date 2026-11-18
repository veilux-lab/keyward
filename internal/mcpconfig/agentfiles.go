package mcpconfig

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/migrate"
)

// AgentFile is a file an AI agent keeps for itself, apart from its MCP servers:
// Claude Code's settings, which hold the commands it was told it may run,
// Codex's config, or an agent's instructions.
type AgentFile struct {
	Path string
	// Project is the folder of the other Claude Code project the file is in, or
	// "" for one in home or the working folder.
	Project string

	// user marks the user's settings, ~/.claude/settings.json: project and local
	// settings, home's local ones too, cannot set Claude Code's OAuth tokens or
	// OpenTelemetry headers.
	user bool
}

// AgentLiteral is a credential written into an agent's own file. It says where
// the credential is, never what it is: the line of instructions it is on, or the
// key of a setting that holds it, with how to take it out.
type AgentLiteral struct {
	File  string
	Line  int
	Field string
	Fix   string
	// Unholdable marks one its agent reads itself, where no cap:// reference can
	// stand in for it.
	Unholdable bool
	migrate.Detection
}

// homeAgentFiles are the files in home that agents keep for themselves, some of
// which keyward agents link writes.
var homeAgentFiles = []string{
	".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
	".codex/config.toml", ".codex/AGENTS.md", ".codex/AGENTS.override.md",
	".copilot/copilot-instructions.md", ".gemini/GEMINI.md",
}

// projectAgentFiles are those in a project's folder.
var projectAgentFiles = []string{
	".claude/settings.json", ".claude/settings.local.json",
	"CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md",
	"AGENTS.md", "AGENTS.override.md", ".github/copilot-instructions.md",
}

// ClaudeProjects returns the folders of Claude Code's projects that still exist,
// sorted, or none if its config cannot be read.
func ClaudeProjects(home string) []string {
	_, projects, _ := loadClaude(filepath.Join(home, ".claude.json"), "", false)
	return slices.DeleteFunc(projects, Gone)
}

// AgentFiles returns the files agents keep for themselves in home, workdir and
// projects, Claude Code's other projects, each once.
func AgentFiles(home, workdir string, projects []string) []AgentFile {
	var files []AgentFile
	seen := map[string]bool{}
	add := func(f AgentFile) {
		if !seen[f.Path] {
			seen[f.Path] = true
			files = append(files, f)
		}
	}
	for _, name := range homeAgentFiles {
		add(AgentFile{Path: filepath.Join(home, name), user: name == ".claude/settings.json"})
	}
	for _, dir := range append([]string{workdir}, projects...) {
		project := dir
		switch dir {
		case "":
			continue
		case workdir:
			project = ""
		}
		for _, name := range projectAgentFiles {
			add(AgentFile{Path: filepath.Join(dir, name), Project: project})
		}
		// Claude Code saves a project's local settings at the root of its repository.
		if root := repositoryRoot(dir); root != "" {
			add(AgentFile{Path: filepath.Join(root, ".claude", "settings.local.json"), Project: project})
		}
	}
	return files
}

// repositoryRoot is the root of the git work tree dir is in, or "" outside one.
// A worktree's is its main checkout's: its .git file names its git dir, whose
// commondir file names the main checkout's.
func repositoryRoot(dir string) string {
	for ; ; dir = filepath.Dir(dir) {
		git := filepath.Join(dir, ".git")
		if _, err := os.Lstat(git); err == nil {
			// A .git folder, which ReadFile cannot read, names no other.
			data, _ := os.ReadFile(git)
			gitdir, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
			if !ok {
				return dir
			}
			if !filepath.IsAbs(gitdir) {
				gitdir = filepath.Join(dir, gitdir)
			}
			common, err := os.ReadFile(filepath.Join(gitdir, "commondir"))
			if err != nil {
				// A submodule's git dir has none.
				return dir
			}
			main := strings.TrimSpace(string(common))
			if !filepath.IsAbs(main) {
				main = filepath.Join(gitdir, main)
			}
			return filepath.Dir(main)
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
}

// Personal returns those of files meant for one person, local settings and
// instructions, and the agents' logins in home, which a repository should not
// track, where git can track them: in a work tree. doctor reads no login, but
// checks git does not track one, in case home is a work tree.
func Personal(home string, files []AgentFile) []string {
	found := []string{filepath.Join(home, ".claude", ".credentials.json"), filepath.Join(home, ".codex", "auth.json")}
	for _, f := range files {
		if base := filepath.Base(f.Path); base == "settings.local.json" || base == "CLAUDE.local.md" {
			found = append(found, f.Path)
		}
	}
	return slices.DeleteFunc(found, func(path string) bool { return repositoryRoot(filepath.Dir(path)) == "" })
}

// Read finds the credentials written into content, the text of a, and the cap://
// references its agent passes from it to the commands it starts, which must
// resolve. A settings file that is not JSON, or a config that is not TOML, is an
// error, as nothing in it was checked.
func (a AgentFile) Read(content []byte) ([]AgentLiteral, []string, error) {
	var found []AgentLiteral
	add := func(field, fix string, unholdable bool, d migrate.Detection) {
		found = append(found, AgentLiteral{File: a.Path, Field: field, Fix: fix, Unholdable: unholdable, Detection: d})
	}
	var passed []string
	var err error
	switch filepath.Ext(a.Path) {
	case ".json":
		passed, err = a.settings(content, add)
	case ".toml":
		passed, err = codexSettings(content, add)
	default:
		for i, line := range strings.Split(string(content), "\n") {
			if d := migrate.InDocument(line); d.Secret {
				found = append(found, AgentLiteral{File: a.Path, Line: i + 1, Detection: d})
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	// Instructions have no field, so a stable sort keeps them in line order.
	slices.SortStableFunc(found, func(x, y AgentLiteral) int { return strings.Compare(x.Field, y.Field) })
	return found, passed, nil
}

// settings calls add with each credential in content, a Claude Code settings
// file, and returns the references its env passes on.
func (a AgentFile) settings(content []byte, add func(field, fix string, unholdable bool, d migrate.Detection)) ([]string, error) {
	var settings map[string]any
	// An empty file sets nothing.
	if err := json.Unmarshal(content, &settings); err != nil && len(bytes.TrimSpace(content)) > 0 {
		return nil, err
	}
	var passed []string
	for k, v := range settings {
		eachString(k, k, v, func(field, key, s string) {
			switch {
			case strings.HasPrefix(field, "env."):
				if handle.IsRef(s) {
					passed = append(passed, s)
				}
				var d migrate.Detection
				headers, listed := headerList(key, s)
				for _, h := range headers {
					if !migrate.Placeholder(h[1]) {
						d = migrate.Surer(d, header(h[0], h[1]))
					}
				}
				if !listed {
					d = detect(key, s)
				}
				// One Claude Code reads itself, but for a list of headers, is a
				// setting unless surely a secret, as a model's ID can look random.
				ownSetting := ownVariable(key) && !listed
				if (d.Secret || d.Possible && !ownSetting) && !migrate.Placeholder(s) {
					fix, unholdable := a.envFix(key)
					add(field, fix, unholdable, d)
				}
			case permissionRule.MatchString(field):
				if command, ok := ruleCommand(s); ok {
					if d := commandSecret(command); d.Secret {
						add(field, ruleFix, false, d)
					}
				}
			case hookHeader.MatchString(field):
				if d := setting(key, s); d.Secret {
					add(field, "Claude Code sends this as written; remove it with Claude Code closed if nothing needs it, or write $VAR in its place and add VAR to allowedEnvVars, "+
						"which Claude Code reads from its own environment, where cap:// does not work", false, d)
				}
			case slices.Contains(printingHelpers, field):
				if d := commandSecret(s); d.Secret {
					add(field, "remove it with Claude Code closed, or have the command read it through keyward run --no-mask", false, d)
				}
			case key == "command" || slices.Contains(helpers, field):
				if d := commandSecret(s); d.Secret {
					add(field, "remove it with Claude Code closed, or have the command read it through keyward run", false, d)
				}
			default:
				if d := setting(key, s); d.Secret {
					add(field, "Claude Code reads this itself; remove it with Claude Code closed if nothing needs it", true, d)
				}
			}
		})
	}
	return passed, nil
}

// codexSettings calls add with each credential in content, Codex's config, but
// its MCP servers, which keyward reads as servers, and returns the references it
// sets for the commands Codex starts.
func codexSettings(content []byte, add func(field, fix string, unholdable bool, d migrate.Detection)) ([]string, error) {
	tables, err := readTOML(string(content))
	if err != nil {
		return nil, err
	}
	var passed []string
	for path, t := range tables {
		parts := strings.Split(path, "\x00")
		if parts[0] == "mcp_servers" || slices.Contains(parts, "env_http_headers") {
			continue
		}
		for key, v := range t {
			if slices.Contains(codexVariables, key) {
				continue
			}
			eachString(strings.TrimPrefix(strings.Join(parts, ".")+"."+key, "."), key, v, func(field, key, s string) {
				if strings.HasPrefix(field, "shell_environment_policy.set.") {
					if handle.IsRef(s) {
						passed = append(passed, s)
					}
					if d := detect(key, s); (d.Secret || d.Possible) && !migrate.Placeholder(s) {
						add(field, passedFix, false, d)
					}
				} else if d := setting(key, s); d.Secret {
					fix, itself := codexFix(field, key)
					add(field, fix, itself, d)
				}
			})
		}
	}
	return passed, nil
}

// ownPrefixes start the names of the variables Claude Code reads itself: its own,
// OpenTelemetry's, and those of Bedrock and Vertex. It reads ownNames too, the
// proxies, in lowercase as well.
var (
	ownPrefixes = []string{"ANTHROPIC_", "CLAUDE_CODE_", "OTEL_", "AWS_", "CLOUD_ML_"}
	ownNames    = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
)

// awsKeys are the AWS credentials awsCredentialExport prints, which Claude Code
// and the commands it starts can both read.
var awsKeys = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}

// passedFix is the fix for a variable an agent passes as written to the commands
// it starts.
const passedFix = "store it with keyward add NAME and set it to cap://NAME, which only keyward run resolves and keyward uninstall does not change back"

// envFix is the fix for a credential in env.name of a's settings, which depends
// on who reads it, and reports whether keyward cannot hold it, as Claude Code
// reads it itself, resolving no reference. A helper it reads a value from gets
// keyward run's mask unless given --no-mask.
func (a AgentFile) envFix(name string) (fix string, unholdable bool) {
	const reads = "Claude Code reads this itself; remove it if nothing needs it"
	const noMask = " (a helper using keyward run needs --no-mask)"
	switch {
	case !a.user && otlpHeaders(name):
		return "remove it, as Claude Code 2.1.282 and later ignore it in project and local settings", false
	case !a.user && (name == "CLAUDE_CODE_OAUTH_TOKEN" || name == "CLAUDE_CODE_OAUTH_REFRESH_TOKEN"):
		return "remove it, as Claude Code ignores it in project and local settings", false
	case name == "ANTHROPIC_API_KEY" || name == "ANTHROPIC_AUTH_TOKEN":
		return reads + ", or have apiKeyHelper print it" + noMask, true
	case otlpHeaders(name):
		return reads + ", or, for HTTP protocols, have otelHeadersHelper print the headers" + noMask, true
	case slices.Contains(awsKeys, name):
		// Both of its readers can get it from keyward.
		return "Claude Code reads this itself for Bedrock, so have awsCredentialExport print the credentials" + noMask +
			"; if only the commands it starts need it, " + passedFix, false
	case ownVariable(name):
		return reads, true
	}
	return passedFix, false
}

// ownVariable reports whether Claude Code reads the variable called name itself.
func ownVariable(name string) bool {
	return slices.Contains(ownNames, strings.ToUpper(name)) || slices.ContainsFunc(ownPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

// otlpHeaders reports whether the variable called name holds OpenTelemetry's
// exporter headers, for all signals or one.
func otlpHeaders(name string) bool {
	return strings.HasPrefix(name, "OTEL_EXPORTER_OTLP_") && strings.HasSuffix(name, "HEADERS")
}

// headerList returns the headers in value, the value of the variable called
// name, if it lists them: OpenTelemetry's as name=value pairs, comma-separated
// and URL-encoded, and ANTHROPIC_CUSTOM_HEADERS as Name: Value lines.
func headerList(name, value string) ([][2]string, bool) {
	var headers [][2]string
	switch {
	case name == "ANTHROPIC_CUSTOM_HEADERS":
		for _, line := range strings.Split(value, "\n") {
			if h, v, ok := cutHeader(line); ok {
				headers = append(headers, [2]string{h, v})
			}
		}
	case otlpHeaders(name):
		for _, pair := range strings.Split(value, ",") {
			h, v, _ := strings.Cut(pair, "=")
			if decoded, err := url.PathUnescape(v); err == nil {
				v = decoded
			}
			headers = append(headers, [2]string{h, v})
		}
	default:
		return nil, false
	}
	return headers, true
}

// helpers are Claude Code's settings that hold a command, as a hook's command
// and the status line's do, under a name that suggests a credential. Claude Code
// reads what printingHelpers print.
var (
	helpers         = []string{"awsAuthRefresh", "gcpAuthRefresh"}
	printingHelpers = []string{"apiKeyHelper", "otelHeadersHelper", "awsCredentialExport"}
)

// ruleFix is the fix for a credential in a permission rule, which Claude Code
// saves from the command it was asked to run.
const ruleFix = "remove the rule with /permissions in Claude Code; a command that reads the secret through keyward run saves none"

// permissionRule matches the field of a permission rule, and hookHeader that of
// an HTTP hook's header, which can read a variable allowedEnvVars lists.
var (
	permissionRule = regexp.MustCompile(`^permissions\.(?:allow|ask|deny)\[[0-9]+\]$`)
	hookHeader     = regexp.MustCompile(`^hooks\.[^.]+\[[0-9]+\]\.hooks\[[0-9]+\]\.headers\.`)
)

// ruleCommand is the command a permission rule for a shell names, without the :*
// that ends a prefix rule and would join its last word, or false for a rule of
// another tool.
func ruleCommand(rule string) (string, bool) {
	for _, tool := range []string{"Bash(", "PowerShell("} {
		if command, ok := strings.CutPrefix(rule, tool); ok {
			return strings.TrimSuffix(strings.TrimSuffix(command, ")"), ":*"), true
		}
	}
	return "", false
}

// mysqls take a password attached to -p or after --password=. The word after a
// bare -p is the database.
var mysqls = []string{"mysql", "mysqldump", "mariadb"}

// switches are the values that turn an option on or off, as yes does in
// MYSQL_ALLOW_EMPTY_PASSWORD=yes, compared without case.
var switches = []string{"yes", "no", "true", "false", "on", "off", "none"}

// commandSecret is the surest credential in command, a command line an agent may
// run, or a script one of its words holds, as sh -c and ssh take one: one
// credentials finds where a word starts, one set by a name that suggests a
// credential, or a password given with its program's option for one. A
// placeholder, a reference and an expansion hold none.
func commandSecret(command string) migrate.Detection {
	var found migrate.Detection
	for _, c := range credentials(command, wordStarts) {
		word := command[c.start:c.end]
		// After a scheme, as Bearer, only a token counts, as in a document: not
		// TOKEN, {token} or a format such as %s.
		if leadingScheme.MatchString(word) {
			c.Secret = migrate.InDocument(word).Secret
		}
		if c.Secret && !migrate.Placeholder(word) {
			found = migrate.Surer(found, c.Detection)
		}
	}
	for _, words := range commandWords(command) {
		program := ""
		for i, w := range words {
			// The command sshpass runs, as ssh, can take a -p of its own.
			sshpass, next := i > 0 && filepath.Base(words[i-1]) == "sshpass", ""
			if i+1 < len(words) {
				next = words[i+1]
			}
			name, value, set := strings.Cut(w, "=")
			var password, reason string
			switch {
			// A person chooses a password, which can be short, so a variable named
			// for one counts at any length, but for a number, a path or a switch.
			case set && assignment.MatchString(w) && (named(name, value) || passwordName.MatchString(name) && strings.Trim(value, "0123456789") != "" &&
				!strings.HasPrefix(value, "/") && !slices.Contains(switches, strings.ToLower(value))):
				password, reason = value, "the variable name suggests a credential"
			case (slices.Contains(mysqls, program) || sshpass) && len(w) > 2 && strings.HasPrefix(w, "-p"):
				password, reason = w[2:], "a password given with -p"
			case slices.Contains(mysqls, program) && set && name == "--password":
				password, reason = value, "a password given with --password"
			case sshpass && w == "-p":
				password, reason = next, "a password given with -p"
			case program == "curl" && (w == "-u" || w == "--user") && login(next):
				password, reason = next, "a user and password given with "+w
			case program == "curl" && set && name == "--user" && login(value):
				password, reason = value, "a user and password given with --user"
			case program == "curl" && strings.HasPrefix(w, "-u") && login(w[2:]):
				password, reason = w[2:], "a user and password given with -u"
			case program == "curl" && (w == "-H" || w == "--header"):
				if h, v, ok := cutHeader(next); ok && named(strings.ReplaceAll(h, "-", "_"), v) {
					password, reason = v, "the header name suggests a credential"
				}
			}
			if password != "" && !handle.IsRef(password) && !migrate.Placeholder(password) && !strings.ContainsAny(password, "$`") {
				found = migrate.Surer(found, migrate.Detection{Secret: true, Reason: reason})
			}
			// A word with spaces in it can be a script, as sh -c and ssh take one.
			if strings.ContainsAny(w, " \t\n") {
				found = migrate.Surer(found, commandSecret(w))
			}
			if base := filepath.Base(w); base == "curl" || slices.Contains(mysqls, base) {
				program = base
			}
		}
	}
	return found
}

// login reports whether s, given to curl -u, is a user and a password, which curl
// splits at the first colon. Without one, curl asks for the password.
func login(s string) bool {
	user, password, ok := strings.Cut(s, ":")
	return ok && user != "" && password != ""
}

// named reports whether Detect calls value, set by name, a secret. One that
// starts with a prefix, as Bearer, is judged where it starts.
func named(name, value string) bool {
	return migrate.CredentialPrefix(value) == "" && migrate.Detect(name, value).Secret
}

// passwordName matches the name of a variable for a password, as PGPASSWORD and
// MYSQL_PWD are.
var passwordName = regexp.MustCompile(`(?i)(?:PASSWORD|PASSWD|PASSPHRASE|(?:^|_)(?:PASS|PWD|PW))$`)

// commandWords splits a command line into the words of each of its commands, as
// sh reads them, or into fields where it cannot, as where a prefix rule ends
// inside a quote.
func commandWords(command string) [][]string {
	words, ok := readScript(command)
	if !ok {
		return [][]string{strings.Fields(command)}
	}
	var commands [][]string
	eachCommand(words, func(_ int, texts []string) { commands = append(commands, texts) })
	return commands
}

// codexVariables are Codex's keys that hold the names of variables, or prose
// about one, rather than values.
var codexVariables = []string{"env_key", "env_key_instructions", "env_http_headers"}

// codexFix is the fix for a credential in field of Codex's config, key's value,
// naming the form that reads it from a variable where Codex documents one, and
// reports whether Codex reads it itself, with no such form. Codex reads those
// from its own environment, where it resolves no reference.
func codexFix(field, key string) (fix string, itself bool) {
	const asWritten = "Codex sends this as written; remove it if nothing needs it"
	const ownEnvironment = "which Codex reads from its own environment, where cap:// does not work"
	provider := strings.HasPrefix(field, "model_providers.")
	header := provider && strings.HasSuffix(field, ".http_headers."+key)
	switch {
	case provider && key == "experimental_bearer_token", header && strings.EqualFold(key, "Authorization"):
		return asWritten + ", or name a variable that holds the key with env_key, " + ownEnvironment +
			", or have auth.command print the token (a command using keyward run needs --no-mask)", false
	case header:
		return asWritten + ", or name a variable that holds it with env_http_headers = { " + strconv.Quote(key) + " = \"VAR\" }, " + ownEnvironment, false
	case strings.HasPrefix(field, "otel."):
		return asWritten, true
	case key == "notify":
		return "Codex runs this as a command; remove it if nothing needs it, or have the command read it through keyward run", false
	}
	return "Codex reads this itself; remove it if nothing needs it", true
}

// setting is what s, the value of key or an item of it, holds by the rules for a
// key keyward keeps in a server, a secret only, with a header's name read as a
// variable's, as X-Api-Key is. A placeholder holds none.
func setting(key, s string) migrate.Detection {
	if migrate.Placeholder(s) {
		return migrate.Detection{}
	}
	return migrate.Surer(header(key, s), argument(s))
}
