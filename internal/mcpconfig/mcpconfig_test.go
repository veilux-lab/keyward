package mcpconfig_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/exposure"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/resolve"
	"github.com/veilux-lab/keyward/internal/shell"
	"github.com/veilux-lab/keyward/internal/vault"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReferencesMapsVariablesToTheirSecrets(t *testing.T) {
	rc := write(t, filepath.Join(t.TempDir(), ".zshrc"), "export EDITOR=vim\nexport GITHUB_TOKEN='cap://github-token'\nJIRA_API_TOKEN=cap://jira-api-token\n")
	got := mcpconfig.References([]string{rc, filepath.Join(t.TempDir(), "missing")})
	if len(got) != 2 || got["GITHUB_TOKEN"] != "github-token" || got["JIRA_API_TOKEN"] != "jira-api-token" {
		t.Errorf("References = %v", got)
	}
}

var refs = map[string]string{"GITHUB_TOKEN": "github-token", "PD_KEY": "pagerduty-key", "JIRA": "jira-token"}

// secrets are fake values for those references.
var secrets = map[string]string{"github-token": "fake-github-value", "pagerduty-key": "fake-pagerduty-value", "jira-token": "fake-jira-value"}

func fixture(t *testing.T) (home, workdir string) {
	t.Helper()
	home, workdir = t.TempDir(), t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{
  "mcpServers": {
    "github": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}},
    "pagerduty": {"command": "uvx", "args": ["pagerduty-mcp"], "env": {"PD_KEY": "${PD_KEY}", "LEVEL": "info", "QUIET": ""}},
    "wrapped": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key"}},
    "aws": {"command": "uvx", "args": ["aws-mcp", "--profile", "dev"]}
  },
  "projects": {"`+workdir+`": {"mcpServers": {"local": {"command": "tool", "args": ["--token", "${JIRA}"]}}}}
}`)
	write(t, filepath.Join(workdir, ".mcp.json"), `{"mcpServers": {"team": {"command": "srv", "env": {"T": "${GITHUB_TOKEN}"}}}}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), `model = "x"

[mcp_servers.github]
url = "https://api.example.com/mcp/"
bearer_token_env_var = "GITHUB_TOKEN" # comment

[mcp_servers.github.tools.create_pull_request]
approval_mode = "approve"

[mcp_servers."atlassian-cloud"]
url = "https://mcp.example.com/v1/mcp"

[mcp_servers."atlassian-cloud".env_http_headers]
Authorization = "JIRA"

[mcp_servers.pagerduty]
command = "uvx"
args = [
  "pagerduty-mcp",
  "--enable-write-tools",
]
env_vars = ["PD_KEY"]
startup_timeout_sec = 60

[mcp_servers.off]
command = "x"
env_vars = ["PD_KEY"]
enabled = false
`)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"gh": {"command": "npx", "args": ["gh-mcp"], "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}}}}`)
	return home, workdir
}

func TestCheckFindsEveryServerThatWouldReceiveAReference(t *testing.T) {
	home, workdir := fixture(t)
	servers, errs := mcpconfig.Load(home, workdir)
	if len(errs) != 0 {
		t.Fatalf("Load errors: %v", errs)
	}
	got := map[string][]string{}
	for _, f := range mcpconfig.Check(servers, refs) {
		got[f.Client+"/"+f.Name] = f.Vars
	}
	want := map[string]string{
		"Claude Code/github": "GITHUB_TOKEN", "Claude Code/pagerduty": "PD_KEY", "Claude Code/local": "JIRA",
		"Claude Code/team": "GITHUB_TOKEN", "Codex/github": "GITHUB_TOKEN", "Codex/atlassian-cloud": "JIRA",
		"Codex/pagerduty": "PD_KEY", "Cursor/gh": "GITHUB_TOKEN",
	}
	if len(got) != len(want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	for name, v := range want {
		if strings.Join(got[name], ",") != v {
			t.Errorf("%s: vars = %v, want %s", name, got[name], v)
		}
	}
}

func finding(t *testing.T, client, name string) mcpconfig.Finding {
	t.Helper()
	home, workdir := fixture(t)
	servers, _ := mcpconfig.Load(home, workdir)
	for _, f := range mcpconfig.Check(servers, refs) {
		if f.Client == client && f.Name == name {
			return f
		}
	}
	t.Fatalf("no finding for %s/%s", client, name)
	return mcpconfig.Finding{}
}

type suggested struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

func parseJSON(t *testing.T, f mcpconfig.Finding) suggested {
	t.Helper()
	var wrapper map[string]suggested
	if err := json.Unmarshal([]byte("{"+f.Suggestion+"}"), &wrapper); err != nil {
		t.Fatalf("suggestion is not a JSON member: %v\n%s", err, f.Suggestion)
	}
	return wrapper[f.Name]
}

// A literal may be a secret, so it is printed as its length and applied as it is.
// An empty value has nothing to hide.
func TestALocalServerIsWrappedDirectly(t *testing.T) {
	f := finding(t, "Claude Code", "pagerduty")
	s := parseJSON(t, f)
	if s.Command != "keyward" || strings.Join(s.Args, " ") != "run --only PD_KEY -- uvx pagerduty-mcp" {
		t.Errorf("command = %s %v", s.Command, s.Args)
	}
	if s.Env["PD_KEY"] != "cap://pagerduty-key" || s.Env["LEVEL"] != "<4 bytes hidden>" || s.Env["QUIET"] != "" || f.Want.Env["LEVEL"] != "info" {
		t.Errorf("printed env = %v, applied env = %v", s.Env, f.Want.Env)
	}
	if !strings.Contains(f.Note, "hidden value") {
		t.Errorf("note does not say where the hidden value comes from: %s", f.Note)
	}
}

// mcpRemoteArgs starts a bridge as its client would, with keyward run resolving
// each reference from secrets and npx replaced by a probe, and returns the
// arguments mcp-remote gets.
func mcpRemoteArgs(t *testing.T, def mcpconfig.Definition) string {
	t.Helper()
	bin := t.TempDir()
	write(t, filepath.Join(bin, "npx"), "#!/bin/sh\nprintf '[%s]' \"$@\"\n")
	if err := os.Chmod(filepath.Join(bin, "npx"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", def.Args[len(def.Args)-1])
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	for k, v := range def.Env {
		if name, ok := strings.CutPrefix(v, "cap://"); ok {
			v = secrets[name]
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// mcp-remote fills ${VAR} in a header from its own environment, so the token never
// enters a command line, where any process can read it. The script must still not
// contain ${, which Claude Code would expand to the reference first.
func TestARemoteServersTokenNeverReachesACommandLine(t *testing.T) {
	f := finding(t, "Claude Code", "github")
	s := parseJSON(t, f)
	if s.Command != "keyward" || len(s.Args) != 7 || s.Args[2] != "GITHUB_TOKEN" || s.Args[4] != "sh" || s.Args[5] != "-c" {
		t.Fatalf("args = %v", s.Args)
	}
	if strings.Contains(s.Args[6], "${") {
		t.Errorf("Claude Code would expand the script: %s", s.Args[6])
	}
	if got, want := mcpRemoteArgs(t, f.Want), "[-y][mcp-remote][https://api.example.com/mcp/][--header][Authorization: Bearer ${GITHUB_TOKEN}][--transport][http-only]"; got != want {
		t.Errorf("mcp-remote args = %s, want %s", got, want)
	}
	if s.Env["GITHUB_TOKEN"] != "cap://github-token" || len(f.InURL) != 0 {
		t.Errorf("env = %v, in URL = %v", s.Env, f.InURL)
	}
}

// A remote server can mix every kind of value. Text written out may be a secret,
// so a value holding any is printed as its length, and a header's text, beside a
// placeholder or not, moves into env, which mcp-remote fills headers from, to keep
// it out of mcp-remote's command line. An auth scheme is not secret and stays.
func TestAMixedRemoteServerKeepsItsLiteralsOutOfCommandLinesAndOutput(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"mixed": {"type": "http", "url": "https://mcp.example.com/mcp?key=${PD_KEY}",
    "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}", "X-Api-Key": "fake-literal-prefix-${JIRA}", "X-Team": "fake-literal-header"},
    "env": {"LEVEL": "fake-literal-env", "DSN": "fake-literal-dsn@${DB_HOST}", "MODE": "${MODE:-fake-literal-default}", "HOST": "${DB_HOST}"}}}}`)
	servers, _ := mcpconfig.Load(home, t.TempDir())
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	f := findings[0]
	if strings.Join(f.Vars, ",") != "GITHUB_TOKEN,JIRA,PD_KEY" || strings.Join(f.InURL, ",") != "PD_KEY" || len(f.Exposed) != 0 {
		t.Errorf("vars = %v, in URL = %v, exposed = %v", f.Vars, f.InURL, f.Exposed)
	}
	if strings.Contains(f.Suggestion+f.Note, "fake-literal") {
		t.Errorf("printed a literal:\n%s\n%s", f.Suggestion, f.Note)
	}
	if s := parseJSON(t, f); s.Env["KW_HDR_1"] != "<20 bytes hidden>" || s.Env["KW_HDR_2"] != "<19 bytes hidden>" || s.Env["LEVEL"] != "<16 bytes hidden>" || s.Env["PD_KEY"] != "cap://pagerduty-key" || s.Env["HOST"] != "${DB_HOST}" {
		t.Errorf("printed env = %v", s.Env)
	}
	if env := f.Want.Env; env["KW_HDR_1"] != "fake-literal-prefix-" || env["KW_HDR_2"] != "fake-literal-header" || env["LEVEL"] != "fake-literal-env" || strings.Join(f.Want.Args[:3], " ") != "run --only GITHUB_TOKEN,JIRA,PD_KEY" {
		t.Errorf("applied = %+v", f.Want)
	}
	if !strings.Contains(f.Note, "KW_HDR_1 holds text from its X-Api-Key header") || !strings.Contains(f.Note, "KW_HDR_2 holds text from its X-Team header") {
		t.Errorf("note does not say which header each KW_HDR variable is from: %s", f.Note)
	}
	// The URL's secret does reach the command line, which is what InURL warns of.
	if got, want := mcpRemoteArgs(t, f.Want), "[-y][mcp-remote][https://mcp.example.com/mcp?key=fake-pagerduty-value][--header][Authorization: Bearer ${GITHUB_TOKEN}][--header][X-Api-Key: ${KW_HDR_1}${JIRA}][--header][X-Team: ${KW_HDR_2}][--transport][http-only]"; got != want {
		t.Errorf("mcp-remote args = %s, want %s", got, want)
	}
}

// Wrapping puts a remote server's URL in mcp-remote's command line. A variable in
// it is a warning only if keyward resolves it, as then its secret would be there
// too; a query string or user info may hold one written out, and a segment of its
// path may be a credential.
func TestAURLIsWarnedOfForWhatMayBeASecret(t *testing.T) {
	for url, want := range map[string]struct {
		inURL        string
		writtenInURL bool
	}{
		"https://${MCP_HOST}/mcp":                                 {"", false},
		"https://mcp.example.com/mcp?key=${PD_KEY}":               {"PD_KEY", true},
		"https://mcp.example.com/mcp?token=fake-url-token":        {"", true},
		"https://fake-user:fake-url-password@mcp.example.com/mcp": {"", true},
		"https://mcp.example.com/" + headerToken + "/mcp":         {"", true},
		"https://mcp.example.com/v1/mcp":                          {"", false},
	} {
		data, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"remote": map[string]any{"type": "http", "url": url,
			"headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}}}})
		if err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		write(t, filepath.Join(home, ".claude.json"), string(data))
		servers, _ := mcpconfig.Load(home, t.TempDir())
		findings := mcpconfig.Check(servers, refs)
		if len(findings) != 1 {
			t.Errorf("%s: findings = %+v", url, findings)
			continue
		}
		if f := findings[0]; strings.Join(f.InURL, ",") != want.inURL || f.WrittenInURL != want.writtenInURL {
			t.Errorf("%s: in URL = %v, written out = %v", url, f.InURL, f.WrittenInURL)
		}
	}
}

// doctor reports a credential in a URL or an argument, so a suggestion prints it
// only as its length, as it does a literal env or header value, and applies it as
// it is. A URL's user info and query values may be secrets too, in each URL an
// argument holds; its variables stay. A PEM block is hidden to its end, as its key
// follows its first word.
func TestSecretsInAURLOrArgumentArePrintedOnlyAsTheirLength(t *testing.T) {
	const pemBody = "FakePemKeyBody00000000000000000000"
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "tenant": {"type": "http", "url": "https://bot:`+urlPassword+`@mcp.example.com/mcp?api_key=`+queryKey+`&key=${PD_KEY}",
      "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}},
    "tool": {"command": "uvx", "args": ["tool-mcp", "--token", "`+argToken+`", "--api-key=`+openAIKey+`",
      "--key", "-----BEGIN PRIVATE KEY-----\n`+pemBody+`\n-----END PRIVATE KEY-----",
      "--proxy=http://proxy.example.com:8080,--db=postgres://admin:`+dbPassword+`@db.example.com/app", "--home", "${HOME}"],
      "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.tenant]\nurl = \"https://"+headerToken+"@mcp.example.com?owner=team@example.com\"\nbearer_token_env_var = \"GITHUB_TOKEN\"\n")
	servers, _ := mcpconfig.Load(home, t.TempDir())
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != 3 {
		t.Fatalf("findings = %+v", findings)
	}
	for _, f := range findings {
		for _, value := range []string{urlPassword, queryKey, argToken, openAIKey, pemBody, dbPassword, headerToken} {
			if strings.Contains(f.Suggestion+f.Note, value) {
				t.Errorf("%s %s printed %q:\n%s\n%s", f.Client, f.Name, value, f.Suggestion, f.Note)
			}
		}
	}
	tenant, tool, codex := findings[0], findings[1], findings[2]
	if got, want := parseJSON(t, tenant).Args[6], `exec npx -y mcp-remote "https://<3 bytes hidden>:<15 bytes hidden>@mcp.example.com/mcp?api_key=<38 bytes hidden>&key=$PD_KEY" `+authHeader+` --transport http-only`; got != want {
		t.Errorf("printed script = %s, want %s", got, want)
	}
	if got, want := mcpRemoteArgs(t, tenant.Want), "[-y][mcp-remote][https://bot:"+urlPassword+"@mcp.example.com/mcp?api_key="+queryKey+"&key=fake-pagerduty-value][--header][Authorization: Bearer ${GITHUB_TOKEN}][--transport][http-only]"; got != want {
		t.Errorf("mcp-remote args = %s, want %s", got, want)
	}
	// Each argument is hidden before sh's quoting joins them into one script.
	if got, want := parseJSON(t, tool).Args[6], `exec uvx tool-mcp --token "<41 bytes hidden>" "--api-key=<39 bytes hidden>" --key "<88 bytes hidden>" "--proxy=http://proxy.example.com:8080,--db=postgres://<5 bytes hidden>:<14 bytes hidden>@db.example.com/app" --home "$HOME"`; got != want {
		t.Errorf("printed script = %s, want %s", got, want)
	}
	if script := tool.Want.Args[6]; !strings.Contains(script, argToken) || !strings.Contains(script, openAIKey) || !strings.Contains(script, pemBody) || !strings.Contains(script, dbPassword) {
		t.Errorf("applied script = %s", script)
	}
	if !strings.Contains(codex.Suggestion, "https://<41 bytes hidden>@mcp.example.com?owner=<16 bytes hidden>") || !strings.Contains(codex.Want.Args[6], headerToken) {
		t.Errorf("suggestion:\n%s\napplied = %v", codex.Suggestion, codex.Want.Args)
	}
	for _, tc := range []struct {
		f      mcpconfig.Finding
		fields string
	}{{tenant, "url"}, {tool, "args[2], args[3], args[5], args[6]"}, {codex, "url"}} {
		if !strings.Contains(tc.f.Note, "Copy each hidden value from the current definition; the hidden text in args is from its "+tc.fields+".") {
			t.Errorf("%s %s: note does not say where the hidden text is from: %s", tc.f.Client, tc.f.Name, tc.f.Note)
		}
	}
}

// doctor flags a token that starts a segment of a URL's path, and a password that
// holds a ? or an @, as user info ends only at an @. Each is printed only as its
// length, and applied as it is. A URL parser reads a ? as the query's start, so
// the host after one is hidden too.
func TestATokenInAURLsPathOrPasswordIsPrintedOnlyAsItsLength(t *testing.T) {
	for _, tc := range []struct{ url, secret, printed string }{
		{"https://mcp.example.com/" + headerToken + "/mcp", headerToken, "https://mcp.example.com/<41 bytes hidden>/mcp"},
		{"https://bot:FakePwHead?FakePwTail@mcp.example.com/mcp", "FakePwHead", "https://<3 bytes hidden>:<41 bytes hidden>"},
		{"https://bot:FakePw@Tail@mcp.example.com/mcp?region=us", "FakePw@Tail", "https://<3 bytes hidden>:<11 bytes hidden>@mcp.example.com/mcp?region=<2 bytes hidden>"},
	} {
		data, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"remote": map[string]any{"type": "http", "url": tc.url,
			"headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}}}})
		if err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		write(t, filepath.Join(home, ".claude.json"), string(data))
		servers, _ := mcpconfig.Load(home, t.TempDir())
		if literals := mcpconfig.Literals(servers); len(literals) != 1 || literals[0].Field != "url" || !literals[0].KnownShape {
			t.Errorf("%s: literals = %+v, want url, of a known shape", tc.url, literals)
		}
		findings := mcpconfig.Check(servers, refs)
		if len(findings) != 1 {
			t.Fatalf("%s: findings = %+v", tc.url, findings)
		}
		f := findings[0]
		if got := parseJSON(t, f).Args[6]; !strings.Contains(got, tc.printed) || strings.Contains(got+f.Note, tc.secret) {
			t.Errorf("printed script = %s, want it to hold %s", got, tc.printed)
		}
		if !strings.Contains(f.Want.Args[6], tc.url) || !strings.HasSuffix(f.Note, "the hidden text in args is from its url.") {
			t.Errorf("applied script = %s, note = %s", f.Want.Args[6], f.Note)
		}
	}
}

// A value after an option named like a credential is printed only as its length
// however short it is, alone or in a script, though doctor, which needs a longer
// one to call it a credential, does not list it. It is applied as it is.
func TestAShortValueAfterAnOptionNamedLikeACredentialIsPrintedOnlyAsItsLength(t *testing.T) {
	values := []string{"Fk9pw2xQ", "Zq3vLm7Rt", "Short7Sec", "shortkey99"}
	args := []string{"--host", "db.internal", "--password", values[0], "--db-password=" + values[1], "--secret", values[2], "--api-key", values[3]}
	for _, args := range [][]string{args, append(args, "--root", "${HOME}")} {
		servers := load(t, "pg", mcpconfig.Definition{Command: "postgres-mcp", Args: args, Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}})
		if literals := mcpconfig.Literals(servers); len(literals) != 0 {
			t.Errorf("literals = %+v", literals)
		}
		findings := mcpconfig.Check(servers, refs)
		if len(findings) != 1 {
			t.Fatalf("findings = %+v", findings)
		}
		f := findings[0]
		for _, value := range values {
			if strings.Contains(f.Suggestion+f.Note, value) {
				t.Errorf("printed %q:\n%s", value, f.Suggestion)
			}
			if !slices.ContainsFunc(f.Want.Args, func(a string) bool { return strings.Contains(a, value) }) {
				t.Errorf("applied args = %q, without %q", f.Want.Args, value)
			}
		}
		if !strings.Contains(f.Suggestion, "db.internal") {
			t.Errorf("the suggestion hides a value no option marks:\n%s", f.Suggestion)
		}
	}
}

// A value after an option named like a credential is printed only as its length
// whatever it holds, a $, a backtick or a leading / included, unless it is only
// variables, and in a server's own script however that is written, when wrap
// rewrites it and when unwrap prints it. doctor reads such a script too, and
// lists a value long enough for it to call a credential.
func TestAnyValueAfterAnOptionNamedLikeACredentialIsPrintedOnlyAsItsLength(t *testing.T) {
	// Each value ends in text that must not be printed, however it is escaped.
	values := map[string]string{"Fk9$Hd2xQ": "Hd2xQ", "ab$Cd12Zk": "Cd12Zk", "Rt5`Lm8vW": "Lm8vW", "/Pq7Ys3nB": "Pq7Ys3nB", "Zq3vLm7RtWx9Kp2Lq": "Zq3vLm7RtWx9Kp2Lq", "Wm4kQ8zLp": "Wm4kQ8zLp"}
	for _, def := range []mcpconfig.Definition{
		{Command: "postgres-mcp", Args: []string{"--password", "Fk9$Hd2xQ", "--api-key=ab$Cd12Zk", "--secret", "Rt5`Lm8vW", "--token", "/Pq7Ys3nB", "--user", "${PG_USER}"},
			Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
		{Command: "sh", Args: []string{"-c", `cd /srv && exec postgres-mcp --password Zq3vLm7RtWx9Kp2Lq --token "${GITHUB_TOKEN}"`}},
		{Command: "bash", Args: []string{"-lc", `postgres-mcp '--password' 'Wm4kQ8zLp' --api-key "$PG_KEY"`}, Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
	} {
		findings := mcpconfig.Check(load(t, "pg", def), refs)
		if len(findings) != 1 {
			t.Fatalf("%q: findings = %+v", def.Args, findings)
		}
		printed := findings[0].Suggestion + findings[0].Note
		for _, f := range mcpconfig.Undo(load(t, "pg", findings[0].Want)) {
			printed += f.Suggestion + f.Note
		}
		for value, tail := range values {
			if strings.Contains(printed, tail) {
				t.Errorf("%q: printed %q:\n%s", def.Args, value, printed)
			}
		}
		for _, variable := range []string{"PG_USER", "GITHUB_TOKEN", "PG_KEY"} {
			if strings.Contains(strings.Join(def.Args, " "), variable) && !strings.Contains(printed, "$"+variable) && !strings.Contains(printed, "${"+variable+"}") {
				t.Errorf("%q: hid %s, which holds no value:\n%s", def.Args, variable, printed)
			}
		}
	}
	script := load(t, "pg", mcpconfig.Definition{Command: "sh", Args: []string{"-c", `cd /srv && exec postgres-mcp --password Zq3vLm7RtWx9Kp2Lq`}})
	if literals := mcpconfig.Literals(script); len(literals) != 1 || literals[0].Field != "args[1]" || !literals[0].Secret {
		t.Errorf("literals = %+v, want the password in args[1]", literals)
	}
}

// What doctor lists as a value that may be a credential is printed only as its
// length: one after an option named like a credential, and a token shaped like a
// key, in an argument, a script or a segment of a URL's path. It is applied as it
// is, and an option's name and a package's are printed as they are.
func TestAValueAnOptionOrItsShapeMarksIsPrintedOnlyAsItsLength(t *testing.T) {
	const (
		hexKey = "0123456789abcdef0123456789abcdef"
		appKey = "Zx8Kq2Lm9Pw4Rt7Yv1Nb5Hc3Jd6Fg0Sa"
		uuid   = "3f2a9c1e-7b4d-4e8f-9a6b-2c1d0e5f7a8b"
		named  = "FakeOpaqueOptionValue"
	)
	args := []string{"-y", "@modelcontextprotocol/server-github", "--api-key", hexKey, "--app-key=" + appKey, "--key", uuid, "--token", named}
	for _, tc := range []struct {
		name   string
		server map[string]any
		shown  []string
	}{
		{"alone", map[string]any{"command": "npx", "args": args, "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
			[]string{`"@modelcontextprotocol/server-github"`, `"--api-key"`, `"<32 bytes hidden>"`, `"--app-key=<32 bytes hidden>"`, `"<36 bytes hidden>"`, `"<21 bytes hidden>"`}},
		{"in a script", map[string]any{"command": "npx", "args": append(args, "--root", "${HOME}"), "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
			[]string{`exec npx -y @modelcontextprotocol/server-github --api-key \"<32 bytes hidden>\" \"--app-key=<32 bytes hidden>\" --key \"<36 bytes hidden>\" --token \"<21 bytes hidden>\" --root \"$HOME\"`}},
		{"in a URL", map[string]any{"type": "http", "url": "https://mcp.example.com/" + uuid + "/sse", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
			[]string{"https://mcp.example.com/<36 bytes hidden>/sse"}},
	} {
		data, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"tool": tc.server}})
		if err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		write(t, filepath.Join(home, ".claude.json"), string(data))
		servers, _ := mcpconfig.Load(home, t.TempDir())
		findings := mcpconfig.Check(servers, refs)
		if len(findings) != 1 {
			t.Fatalf("%s: findings = %+v", tc.name, findings)
		}
		f := findings[0]
		for _, value := range []string{hexKey, appKey, uuid, named} {
			if strings.Contains(f.Suggestion+f.Note, value) {
				t.Errorf("%s: printed %q:\n%s\n%s", tc.name, value, f.Suggestion, f.Note)
			}
		}
		for _, want := range tc.shown {
			if !strings.Contains(f.Suggestion, want) {
				t.Errorf("%s: the suggestion lacks %s:\n%s", tc.name, want, f.Suggestion)
			}
		}
		if applied := strings.Join(f.Want.Args, " "); !strings.Contains(applied, uuid) {
			t.Errorf("%s: applied args = %s, want them as they are", tc.name, applied)
		}
	}
}

// A credential in JSON, a dict or a list, spaced or not, is printed only as its
// length by wrap and unwrap, alone or in a script, and applied as it is. host:port,
// a URL's scheme, a time and a:b hold none, so they print as they are.
func TestACredentialInJSONOrAListIsPrintedOnlyAsItsLength(t *testing.T) {
	plain := []string{"mcp.example.com:8443", "https://mcp.example.com/mcp", "--window=09:30-17:45", "--locales=slovak:sk-SK,czech:cs-CZ",
		"--mirrors=eu.example.com:443,sk-mirror.example.com:443", `{"url":"https://mcp.example.com/mcp","at":"09:30"}`}
	for _, tc := range []struct{ arg, value, printed string }{
		{`{"githubPersonalAccessToken":"` + compactToken + `"}`, compactToken, `{"githubPersonalAccessToken":"<39 bytes hidden>"}`},
		{`{'apiKey':'` + anthropicKey + `'}`, anthropicKey, `{'apiKey':'<43 bytes hidden>'}`},
		{`{ "apiKey" :"` + anthropicKey + `" }`, anthropicKey, `{ "apiKey" :"<43 bytes hidden>" }`},
		{`["--verbose","` + anthropicKey + `"]`, anthropicKey, `["--verbose","<43 bytes hidden>"]`},
	} {
		for _, script := range []bool{false, true} {
			args := append([]string{"-y", "@org/server", "--config", tc.arg}, plain...)
			if script {
				args = append(args, "--root", "${HOME}")
			}
			findings := mcpconfig.Check(load(t, "cfg", mcpconfig.Definition{Command: "npx", Args: args, Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}), refs)
			if len(findings) != 1 {
				t.Fatalf("findings = %+v", findings)
			}
			undo := mcpconfig.Undo(load(t, "cfg", findings[0].Want))
			if len(undo) != 1 {
				t.Fatalf("findings once wrapped = %+v", undo)
			}
			// What each prints, its field in the current definition, and what it applies.
			wrap, unwrap := findings[0], undo[0]
			printed := slices.Concat([]string{"npx"}, args[:3], []string{tc.printed}, plain)
			fields := []string{"args[3]", "args[8]"}
			if script {
				printed = []string{`exec npx -y @org/server --config "` + strings.ReplaceAll(tc.printed, `"`, `\"`) + `" ` + strings.Join(plain[:5], " ") +
					` "` + strings.ReplaceAll(plain[5], `"`, `\"`) + `" --root "$HOME"`}
				fields = []string{"args[3]", "args[6]"}
			}
			for i, f := range []mcpconfig.Finding{wrap, unwrap} {
				s := parseJSON(t, f)
				if got := append([]string{s.Command}, s.Args...); !slices.Equal(got[len(got)-len(printed):], printed) {
					t.Errorf("printed %q\nwant it to end %q", got, printed)
				}
				if strings.Contains(f.Suggestion+f.Note, tc.value) || !strings.HasSuffix(f.Note, "the hidden text in args is from its "+fields[i]+".") {
					t.Errorf("printed %q, or the note does not name %s:\n%s\n%s", tc.value, fields[i], f.Suggestion, f.Note)
				}
				if !slices.ContainsFunc(f.Want.Args, func(a string) bool { return strings.Contains(a, tc.value) }) {
					t.Errorf("applied args = %q", f.Want.Args)
				}
			}
		}
	}
}

// A header given to mcp-remote as an argument, after --header or in --header=,
// spaced or not, is printed by wrap and unwrap as a bridge's is: its name, auth
// scheme and placeholders as they are, its text only as its length, alone or in
// the script wrap writes. It is applied as it is.
func TestAHeaderArgumentIsPrintedOnlyAsItsLength(t *testing.T) {
	hidden := func(v string) string { return fmt.Sprintf("<%d bytes hidden>", len(v)) }
	for _, script := range []bool{false, true} {
		args := []string{"-y", "mcp-remote", "https://api.example.com/mcp", "--header", "X-Api-Key: " + opaqueHeader, "--header", "X-Other-Key:" + noSpaceKey,
			"--header=X-Auth: Token " + schemeToken, "--header", "DD-API-KEY: " + hexHeader, "--header", "X-Upstream:Bearer " + opaqueToken}
		env := map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}
		fields := []string{"args[4], args[6], args[7], args[9], args[11]", "args[9], args[11], args[12], args[14], args[16]"}
		// A header that reads a variable has wrap put them all in a script, which
		// leaves the variable to mcp-remote.
		if script {
			args, env = append(args, "--header", "Authorization: Bearer ${GITHUB_TOKEN}"), nil
			fields[1] = "args[6]"
		}
		findings := mcpconfig.Check(load(t, "remote", mcpconfig.Definition{Command: "npx", Args: args, Env: env}), refs)
		if len(findings) != 1 {
			t.Fatalf("findings = %+v", findings)
		}
		undo := mcpconfig.Undo(load(t, "remote", findings[0].Want))
		if len(undo) != 1 {
			t.Fatalf("findings once wrapped = %+v", undo)
		}
		for i, f := range []mcpconfig.Finding{findings[0], undo[0]} {
			for _, value := range []string{opaqueHeader, noSpaceKey, schemeToken, hexHeader, opaqueToken} {
				if strings.Contains(f.Suggestion+f.Note, value) {
					t.Errorf("printed %q:\n%s\n%s", value, f.Suggestion, f.Note)
				}
				if !slices.ContainsFunc(f.Want.Args, func(a string) bool { return strings.Contains(a, value) }) {
					t.Errorf("applied args = %q, without %q", f.Want.Args, value)
				}
			}
			for _, want := range []string{"X-Api-Key: " + hidden(opaqueHeader), "X-Other-Key:" + hidden(noSpaceKey), "--header=X-Auth: Token " + hidden(schemeToken),
				"DD-API-KEY: " + hidden(hexHeader), "X-Upstream:Bearer " + hidden(opaqueToken)} {
				if !strings.Contains(f.Suggestion, want) {
					t.Errorf("suggestion lacks %s:\n%s", want, f.Suggestion)
				}
			}
			if script && !strings.Contains(f.Suggestion, `--header \"Authorization: Bearer \"'$''{GITHUB_TOKEN}'\"\"`) {
				t.Errorf("suggestion lost the header's placeholder:\n%s", f.Suggestion)
			}
			if !strings.HasSuffix(f.Note, "the hidden text in args is from its "+fields[i]+".") {
				t.Errorf("note = %s, want it to name %s", f.Note, fields[i])
			}
		}
	}
}

// The note names the fields of the definition as written. A bridge has no url, as
// its URL is in its script, and its header's text moves to env, hiding nothing in
// its args. A command can begin like a credential too.
func TestTheNoteNamesWhereTheCurrentDefinitionHoldsTheHiddenText(t *testing.T) {
	for _, tc := range []struct {
		def  mcpconfig.Definition
		note string
	}{
		{bridge(`exec npx -y mcp-remote "https://mcp.example.com/mcp?api_key=` + queryKey + `" --header "Authorization: Bearer $GITHUB_TOKEN"`),
			"the hidden text in args is from its args[6]."},
		{bridge(`exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` --header "X-Api-Key: ` + headerToken + `" --transport http-only`),
			"KW_HDR_1 holds text from its X-Api-Key header."},
		{mcpconfig.Definition{Command: "sk-tool", Args: []string{"serve"}, Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
			"the hidden text in args is from its command."},
	} {
		findings := mcpconfig.Check(load(t, "tool", tc.def), refs)
		if len(findings) != 1 {
			t.Fatalf("findings = %+v", findings)
		}
		if note := findings[0].Note; !strings.HasSuffix(note, " Copy each hidden value from the current definition; "+tc.note) {
			t.Errorf("note = %s, want it to end %q", note, tc.note)
		}
	}
}

// Earlier versions of keyward let sh expand the header, putting the token in
// mcp-remote's command line. Those bridges are offered the current form.
func TestAnEarlierBridgeThatExposesTheTokenIsWrappedAgain(t *testing.T) {
	findings := mcpconfig.Check(wrapped(t), refs)
	if len(findings) != 1 || findings[0].Name != "github" || strings.Join(findings[0].Exposed, ",") != "GITHUB_TOKEN" || strings.Join(findings[0].Vars, ",") != "GITHUB_TOKEN" {
		t.Fatalf("findings = %+v", findings)
	}
	s := parseJSON(t, findings[0])
	if got, want := mcpRemoteArgs(t, findings[0].Want), "[-y][mcp-remote][https://api.example.com/mcp/][--header][Authorization: Bearer ${GITHUB_TOKEN}][--transport][http-only]"; got != want {
		t.Errorf("mcp-remote args = %s, want %s", got, want)
	}
	if strings.Join(s.Args[:4], " ") != "run --only GITHUB_TOKEN --" || s.Env["GITHUB_TOKEN"] != "cap://github-token" {
		t.Errorf("suggestion = %+v", s)
	}
}

// load writes a Claude Code config holding def as the server name, and reads it.
func load(t *testing.T, name string, def mcpconfig.Definition) []mcpconfig.Server {
	t.Helper()
	data, err := json.Marshal(map[string]any{"mcpServers": map[string]any{name: map[string]any{"command": def.Command, "args": def.Args, "env": def.Env}}})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), string(data))
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 || len(servers) != 1 {
		t.Fatalf("servers = %+v, errors = %v", servers, errs)
	}
	return servers
}

// bridge starts script through keyward, as the bridges keyward writes do.
func bridge(script string) mcpconfig.Definition {
	return mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "GITHUB_TOKEN,PD_KEY", "--", "sh", "-c", script},
		Env: map[string]string{"GITHUB_TOKEN": "cap://github-token", "PD_KEY": "cap://pagerduty-key"}}
}

const authHeader = `--header "Authorization: Bearer "'$''{GITHUB_TOKEN}'""`

// From 1.1.4 keyward leaves a header's ${VAR} for mcp-remote to fill in, but a
// header's text goes in as written, and sh still expands a variable in the URL.
// A credential in the text, or the variable, is then in mcp-remote's command line,
// so the bridge is reported. Its header's text is wrapped again through env; its
// URL keeps the secret, which the wrap warns of.
func TestACurrentBridgeIsReportedForWhatItPutsInACommandLine(t *testing.T) {
	for _, tc := range []struct{ script, exposed, inURL, args string }{
		{`exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` --header "X-Team-Token: fake-literal-header" --transport http-only`, "the X-Team-Token header", "",
			"[-y][mcp-remote][https://api.example.com/mcp/][--header][Authorization: Bearer ${GITHUB_TOKEN}][--header][X-Team-Token: ${KW_HDR_1}][--transport][http-only]"},
		{`exec npx -y mcp-remote https://api.example.com/mcp/ --header "X-Api-Key: fake-literal-prefix-"'$''{PD_KEY}'"" --transport http-only`, "the X-Api-Key header", "",
			"[-y][mcp-remote][https://api.example.com/mcp/][--header][X-Api-Key: ${KW_HDR_1}${PD_KEY}][--transport][http-only]"},
		{`exec npx -y mcp-remote "https://api.example.com/mcp?key=$PD_KEY" --header "Authorization: Bearer $GITHUB_TOKEN" --transport http-only`, "GITHUB_TOKEN,PD_KEY", "PD_KEY",
			"[-y][mcp-remote][https://api.example.com/mcp?key=fake-pagerduty-value][--header][Authorization: Bearer ${GITHUB_TOKEN}][--transport][http-only]"},
	} {
		findings := mcpconfig.Check(load(t, "github", bridge(tc.script)), refs)
		if len(findings) != 1 {
			t.Errorf("findings for %s = %+v", tc.script, findings)
			continue
		}
		f := findings[0]
		if strings.Join(f.Exposed, ",") != tc.exposed || strings.Join(f.InURL, ",") != tc.inURL || strings.Contains(f.Suggestion, "fake-literal") {
			t.Errorf("exposed = %v, in URL = %v, suggestion:\n%s", f.Exposed, f.InURL, f.Suggestion)
		}
		if got := mcpRemoteArgs(t, f.Want); got != tc.args {
			t.Errorf("mcp-remote args = %s, want %s", got, tc.args)
		}
	}
}

// A bridge an earlier keyward wrote can send an ordinary header written out, as
// Accept or a client's name, which mcp-remote has in its command line but which
// holds no secret. Only header text that the header's name or value marks as a
// credential, as doctor judges a header, counts as a secret there.
func TestABridgesOrdinaryHeaderIsNoSecretInItsCommandLine(t *testing.T) {
	const ordinary = `--header "Accept: application/json, text/event-stream" --header "X-Client-Name: claude-code"`
	for _, tc := range []struct{ script, exposed string }{
		{`exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` ` + ordinary + ` --transport http-only`, ""},
		{`exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` ` + ordinary + ` --header "X-Api-Key: fake-literal-api-key" --transport http-only`, "the X-Api-Key header"},
		{`exec npx -y mcp-remote https://api.example.com/mcp/ ` + ordinary + ` --header "Authorization: Bearer fake-literal" --transport http-only`, "the Authorization header"},
	} {
		var exposed []string
		for _, f := range mcpconfig.Check(load(t, "api", bridge(tc.script)), refs) {
			exposed = append(exposed, f.Exposed...)
		}
		if strings.Join(exposed, ",") != tc.exposed {
			t.Errorf("%s: exposed = %v, want %s", tc.script, exposed, tc.exposed)
		}
	}
}

// A bridge whose only exposure is a secret in its URL would be wrapped again
// unchanged, as only header authentication can help. It is reported with no
// replacement, so nothing offers a change that changes nothing.
func TestABridgeExposingOnlyItsURLHasNoReplacement(t *testing.T) {
	findings := mcpconfig.Check(load(t, "github", bridge(`exec npx -y mcp-remote "https://api.example.com/mcp?key=$PD_KEY" `+authHeader+` --transport http-only`)), refs)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	if f := findings[0]; strings.Join(f.Exposed, ",") != "PD_KEY" || strings.Join(f.InURL, ",") != "PD_KEY" || f.Suggestion != "" || f.Want.Command != "" || !strings.Contains(f.Note, "already runs through keyward") {
		t.Errorf("finding = %+v", f)
	}
}

// keyward mcp reports a bridge as exposing a secret exactly when doctor, which
// looks for stored values in running programs' command lines, finds one in it.
func TestABridgeIsReportedExactlyWhenDoctorFindsASecretInItsCommandLine(t *testing.T) {
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"github-token": secrets["github-token"], "pagerduty-key": secrets["pagerduty-key"],
		"team-key": "fake-literal-header", "key-prefix": "fake-literal-prefix"}); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"earlier":                   `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer $GITHUB_TOKEN"`,
		"current":                   `exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` --transport http-only`,
		"secret in URL":             `exec npx -y mcp-remote "https://api.example.com/mcp?key=$PD_KEY" ` + authHeader + ` --transport http-only`,
		"literal header":            `exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` --header "X-Team-Token: fake-literal-header" --transport http-only`,
		"ordinary header":           `exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` --header "Accept: application/json, text/event-stream" --transport http-only`,
		"text beside a placeholder": `exec npx -y mcp-remote https://api.example.com/mcp/ --header "X-Api-Key: fake-literal-prefix-"'$''{PD_KEY}'"" --transport http-only`,
		"reference in a header":     `exec npx -y mcp-remote https://api.example.com/mcp/ --header "X-Team: cap://team-key" --transport http-only`,
	} {
		def := bridge(script)
		found, err := exposure.Find(store, []exposure.Process{{PID: 1, Path: "/usr/local/bin/node", Args: []string{mcpRemoteArgs(t, def)}}})
		if err != nil {
			t.Fatal(err)
		}
		findings := mcpconfig.Check(load(t, "github", def), refs)
		if reported := len(findings) == 1 && len(findings[0].Exposed) > 0; reported != (len(found) > 0) {
			t.Errorf("%s: keyward mcp reports %+v, doctor finds %+v", name, findings, found)
		}
	}
}

// mcp-remote takes as its URL the first argument that is neither a --header or
// --header-file nor the value after one, so a URL after the headers is judged as
// one before them is: the secret it reads goes in mcp-remote's command line. Once
// wrapped, such a bridge is read back as keyward's, whose URL alone exposes it, in
// whatever order its words are.
func TestAURLAfterMCPRemotesHeadersIsJudgedAsItsURL(t *testing.T) {
	const url = "https://mcp.example.com/v1/mcp?key=${PD_KEY}"
	for _, tc := range []struct {
		def      mcpconfig.Definition
		readBack bool
	}{
		{mcpconfig.Definition{Command: "npx", Args: []string{"-y", "mcp-remote", "--header", "Authorization: Bearer ${JIRA}", url, "--transport", "http-only"}}, true},
		{mcpconfig.Definition{Command: "sh", Args: []string{"-c", `exec npx -y mcp-remote --header "Authorization: Bearer ${JIRA}" "` + url + `" --transport http-only`}}, true},
		{mcpconfig.Definition{Command: "npx", Args: []string{"-y", "mcp-remote", "--header-file", "/etc/mcp-headers", "--header", "Authorization: Bearer ${JIRA}", url}}, false},
	} {
		findings := mcpconfig.Check(load(t, "remote", tc.def), refs)
		if len(findings) != 1 {
			t.Errorf("%q: findings = %+v", tc.def.Args, findings)
			continue
		}
		f := findings[0]
		if strings.Join(f.InURL, ",") != "PD_KEY" || !f.WrittenInURL || f.ByHand {
			t.Errorf("%q: in URL = %v, written out = %v, by hand = %v", tc.def.Args, f.InURL, f.WrittenInURL, f.ByHand)
		}
		if !tc.readBack {
			continue
		}
		if again := mcpconfig.Check(load(t, "remote", f.Want), refs); len(again) != 1 || strings.Join(again[0].Exposed, ",") != "PD_KEY" ||
			strings.Join(again[0].InURL, ",") != "PD_KEY" || again[0].Suggestion != "" {
			t.Errorf("%q wrapped is reported as %+v, want its URL alone to expose PD_KEY", tc.def.Args, again)
		}
	}
}

// A bridge written by hand is not read as keyward's, so Check finds nothing in it
// to rewrite. One whose sh passes mcp-remote a secret in a header, as any
// script's argument is, with $(...) or without, is reported, as keyward run
// refuses to start it, with nothing to change. One whose script reads ${JIRA}
// gets the reference, as its client fills that in before keyward run starts, so
// it is reported for that alone, as any wrapped command would be.
func TestAHandWrittenBridgeIsNotReadAsKeywards(t *testing.T) {
	def := func(script string) mcpconfig.Definition {
		return mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA", "--", "sh", "-c", script}, Env: map[string]string{"JIRA": "cap://jira-token"}}
	}
	for _, script := range []string{
		`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Basic $(printf '%s' "$JIRA" | base64)"`,
		`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header 'Authorization: Bearer '"$JIRA"`,
	} {
		findings := mcpconfig.Check(load(t, "atlassian", def(script)), refs)
		if len(findings) != 1 || !findings[0].Refused || strings.Join(findings[0].CommandLine, ",") != "JIRA" || len(findings[0].InURL) != 0 || findings[0].Suggestion != "" {
			t.Errorf("findings for %s = %+v", script, findings)
		}
	}
	script := `exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer "'${JIRA}'""`
	findings := mcpconfig.Check(load(t, "atlassian", def(script)), refs)
	if len(findings) != 1 || strings.Join(findings[0].InArgs, ",") != "JIRA" || len(findings[0].Exposed) != 0 || findings[0].Refused || len(findings[0].CommandLine) != 0 {
		t.Errorf("findings for %s = %+v", script, findings)
	}
}

// An SSE server needs another transport than http-only, and wrapping a stdio
// mcp-remote keeps the one it names, or none, which leaves mcp-remote's default,
// so keyward writes such bridges too. One that puts a secret in a command line is
// reported, and written again with its own transport, or none; one that puts none
// there is left alone.
func TestABridgeKeepsItsTransport(t *testing.T) {
	for _, tc := range []struct{ script, exposed, args string }{
		{`exec npx -y mcp-remote https://mcp.example.com/v1/sse --transport sse-only --header "Authorization: Bearer $JIRA"`, "JIRA",
			"[-y][mcp-remote][https://mcp.example.com/v1/sse][--header][Authorization: Bearer ${JIRA}][--transport][sse-only]"},
		{`exec npx -y mcp-remote https://mcp.example.com/v1/sse --header "Authorization: Bearer "'$''{JIRA}'"" --header "X-Team-Token: fake-literal-header" --transport http-first`, "the X-Team-Token header",
			"[-y][mcp-remote][https://mcp.example.com/v1/sse][--header][Authorization: Bearer ${JIRA}][--header][X-Team-Token: ${KW_HDR_1}][--transport][http-first]"},
		{`exec npx -y mcp-remote https://mcp.example.com/v1/sse --header "Authorization: Bearer $JIRA"`, "JIRA",
			"[-y][mcp-remote][https://mcp.example.com/v1/sse][--header][Authorization: Bearer ${JIRA}]"},
	} {
		def := mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA", "--", "sh", "-c", tc.script}, Env: map[string]string{"JIRA": "cap://jira-token"}}
		findings := mcpconfig.Check(load(t, "atlassian", def), refs)
		if len(findings) != 1 {
			t.Errorf("findings for %s = %+v", tc.script, findings)
			continue
		}
		f := findings[0]
		if strings.Join(f.Exposed, ",") != tc.exposed || strings.Contains(f.Suggestion, "fake-literal") {
			t.Errorf("exposed = %v, suggestion:\n%s", f.Exposed, f.Suggestion)
		}
		if got := mcpRemoteArgs(t, f.Want); got != tc.args {
			t.Errorf("mcp-remote args = %s, want %s", got, tc.args)
		}
		if again := mcpconfig.Check(load(t, "atlassian", f.Want), refs); len(again) != 0 {
			t.Errorf("reported again once applied: %+v", again)
		}
	}
	safe := mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA", "--", "sh", "-c",
		`exec npx -y mcp-remote https://mcp.example.com/v1/sse --header "Authorization: Bearer "'$''{JIRA}'"" --transport sse-only`}, Env: map[string]string{"JIRA": "cap://jira-token"}}
	if findings := mcpconfig.Check(load(t, "atlassian", safe), refs); len(findings) != 0 {
		t.Errorf("findings for a bridge that exposes nothing = %+v", findings)
	}
}

// mcp-remote's http-only never falls back to SSE, so a server whose type is sse,
// in Claude Code or Cursor, is bridged with sse-only, and one of another type with
// http-only. Once wrapped, the bridge is not reported again, and Undo, which keeps
// the bridge, keeps its transport.
func TestAnSSEServerIsBridgedOverSSE(t *testing.T) {
	for client, path := range map[string]string{"Claude Code": ".claude.json", "Cursor": filepath.Join(".cursor", "mcp.json")} {
		home := t.TempDir()
		data, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
			"linear": map[string]any{"type": "sse", "url": "https://mcp.example.com/sse", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
			"github": map[string]any{"type": "http", "url": "https://api.example.com/mcp/", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}}}})
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(home, path), string(data))
		servers, errs := mcpconfig.Load(home, t.TempDir())
		if len(errs) != 0 {
			t.Fatal(errs)
		}
		findings := mcpconfig.Check(servers, refs)
		if len(findings) != 2 {
			t.Fatalf("%s: findings = %+v", client, findings)
		}
		for _, f := range findings {
			transport := map[string]string{"linear": "sse-only", "github": "http-only"}[f.Name]
			if got := mcpRemoteArgs(t, f.Want); !strings.HasSuffix(got, "[--transport]["+transport+"]") {
				t.Errorf("%s %s: mcp-remote args = %s, want --transport %s", client, f.Name, got, transport)
			}
			bridged := load(t, f.Name, f.Want)
			if again := mcpconfig.Check(bridged, refs); len(again) != 0 {
				t.Errorf("%s %s: reported again once wrapped: %+v", client, f.Name, again)
			}
			if undo := mcpconfig.Undo(bridged); len(undo) != 1 || !strings.HasSuffix(undo[0].Want.Args[len(undo[0].Want.Args)-1], " --transport "+transport) {
				t.Errorf("%s %s: undo = %+v, want the bridge with --transport %s", client, f.Name, undo, transport)
			}
		}
	}
}

// A script that starts mcp-remote in a way keyward does not read as a bridge, as
// with a callback port or another of mcp-remote's options, still has sh expand a
// secret in the URL into mcp-remote's command line. It is reported for that, with
// nothing to change, as only header authentication would take it out; one whose
// URL expands no secret is not.
func TestAScriptNotReadAsABridgeIsReportedForASecretInItsURL(t *testing.T) {
	for script, exposed := range map[string]string{
		`exec npx -y mcp-remote "https://mcp.example.com/sse?key=$PD_KEY" 3334 --header "Authorization: Bearer "'$''{JIRA}'""`:         "PD_KEY",
		`exec npx -y mcp-remote "https://mcp.example.com/sse?key=$PD_KEY" --allow-http`:                                                "PD_KEY",
		`cd / && exec npx -y mcp-remote --header "Authorization: Bearer "'$''{JIRA}'"" "https://mcp.example.com/sse?key=$PD_KEY" 3334`: "PD_KEY",
		`exec npx -y mcp-remote https://mcp.example.com/sse 3334 --header "Authorization: Bearer "'$''{JIRA}'""`:                       "",
		`exec npx -y mcp-remote "https://mcp.example.com/sse?home=$HOME" 3334`:                                                         "",
	} {
		def := mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA,PD_KEY", "--", "sh", "-c", script},
			Env: map[string]string{"JIRA": "cap://jira-token", "PD_KEY": "cap://pagerduty-key"}}
		findings := mcpconfig.Check(load(t, "remote", def), refs)
		if exposed == "" {
			if len(findings) != 0 {
				t.Errorf("%s: findings = %+v", script, findings)
			}
			continue
		}
		if len(findings) != 1 || strings.Join(findings[0].Exposed, ",") != exposed || strings.Join(findings[0].InURL, ",") != exposed ||
			findings[0].Suggestion != "" || findings[0].ByHand || !strings.Contains(findings[0].Note, "already runs through keyward") {
			t.Errorf("%s: findings = %+v, want its URL to expose %s", script, findings, exposed)
		}
	}
}

// A server whose own script starts keyward run, as zsh -lc "keyward run ..." does
// to get a login shell's PATH, runs through keyward too, so it is checked as
// keyward run checks it, with the secrets its environment or the client's holds.
// One keyward run refuses is reported, with what keyward run says, to change by
// hand, as wrap does not rewrite such a script. None is wrapped again.
func TestAServerWhoseScriptStartsKeywardRunIsCheckedAsOne(t *testing.T) {
	for _, tc := range []struct {
		script string
		env    map[string]string
		why    string
	}{
		{`keyward run --only JIRA -- sh -c 'exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer $JIRA"'`, map[string]string{"JIRA": "cap://jira-token"},
			"npx would get JIRA in its command line (line 1), where other programs and security logs can read it."},
		{`cd / && exec /opt/homebrew/bin/keyward run --only JIRA -- sh -c 'exec slack-mcp --token "$JIRA"'`, nil,
			"slack-mcp would get JIRA in its command line (line 1), where other programs and security logs can read it."},
		{`keyward run --only JIRA -- sh -c 'JIRA_TOKEN="$JIRA" exec jira-mcp'`, map[string]string{"JIRA": "cap://jira-token"}, ""},
		{`keyward run --allow-command-line --only JIRA -- sh -c 'exec slack-mcp --token "$JIRA"'`, map[string]string{"JIRA": "cap://jira-token"}, ""},
	} {
		findings := mcpconfig.Check(load(t, "jira", mcpconfig.Definition{Command: "/bin/zsh", Args: []string{"-lc", tc.script}, Env: tc.env}), refs)
		if tc.why == "" {
			if len(findings) != 0 {
				t.Errorf("%s: findings = %+v", tc.script, findings)
			}
			continue
		}
		if len(findings) != 1 {
			t.Fatalf("%s: findings = %+v", tc.script, findings)
		}
		if f := findings[0]; !f.Refused || !f.ByHand || f.Want.Command != "" || len(f.Reasons) != 1 || f.Reasons[0].Why != tc.why ||
			!strings.Contains(f.Note, "give that keyward run --allow-command-line") {
			t.Errorf("%s: finding = %+v", tc.script, f)
		}
	}
}

// A server's script that passes a secret keyward run resolves to a program as an
// argument puts it in that program's command line, as wrap's own script does for
// a server that takes its token with --token, and an earlier keyward's for a
// server's own sh -c, so keyward run refuses to start it. It is reported with
// nothing keyward can change, as only the server can take it another way, and
// one in mcp-remote's URL as in its URL. Setting a variable, a shell builtin, as
// printf piping it to stdin, though not one exec runs, and a variable that holds
// no secret do not count.
func TestAWrappedScriptThatPassesASecretAsAnArgumentIsReported(t *testing.T) {
	for _, tc := range []struct{ script, commandLine, inURL string }{
		{`exec npx -y slack-mcp --token "$GITHUB_TOKEN"`, "GITHUB_TOKEN", ""},
		{`cd /srv && exec bash -c "exec some-mcp --token $GITHUB_TOKEN --key $PD_KEY"`, "GITHUB_TOKEN,PD_KEY", ""},
		{`exec npx -y mcp-remote https://mcp.example.com/v1/mcp 3334 --header "Authorization: Bearer $GITHUB_TOKEN"`, "GITHUB_TOKEN", ""},
		{`exec npx -y mcp-remote "https://mcp.example.com/sse?key=$PD_KEY" 3334 --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'""`, "PD_KEY", "PD_KEY"},
		{`exec printf '[%s]' "$PD_KEY"`, "PD_KEY", ""},
		{`GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN" exec github-mcp-server stdio`, "", ""},
		{`export TOKEN="$GITHUB_TOKEN"; printf '%s' "$PD_KEY" | exec some-mcp --key-stdin`, "", ""},
		{`exec some-mcp --root "$HOME"`, "", ""},
	} {
		def := mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "GITHUB_TOKEN,PD_KEY", "--", "sh", "-c", tc.script},
			Env: map[string]string{"GITHUB_TOKEN": "cap://github-token", "PD_KEY": "cap://pagerduty-key"}}
		findings := mcpconfig.Check(load(t, "tool", def), refs)
		if tc.commandLine == "" {
			if len(findings) != 0 {
				t.Errorf("%s: findings = %+v", tc.script, findings)
			}
			continue
		}
		if len(findings) != 1 {
			t.Errorf("%s: findings = %+v", tc.script, findings)
			continue
		}
		if f := findings[0]; strings.Join(f.CommandLine, ",") != tc.commandLine || strings.Join(f.InURL, ",") != tc.inURL || !f.Refused || f.Suggestion != "" || f.Want.Command != "" || f.ByHand {
			t.Errorf("%s: finding = %+v, want %s in a command line and nothing to change", tc.script, f, tc.commandLine)
		}
	}
}

// A server keyward run refuses carries what keyward run says of it, so keyward
// mcp can give the same reasons: of the server as configured, or of the change
// wrap would make, for a script the definition holds. Each fix is a server's,
// which never sends a value on stdin, where the server reads the protocol. One
// wrap would write from a server's arguments is not in the definition, so it
// carries none.
func TestARefusedServerCarriesWhatKeywardRunSaysOfIt(t *testing.T) {
	wrapped := func(shell, script string) mcpconfig.Definition {
		return mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA,PD_KEY", "--", shell, "-c", script},
			Env: map[string]string{"JIRA": "cap://jira-token", "PD_KEY": "cap://pagerduty-key"}}
	}
	for _, tc := range []struct {
		shape    string
		def      mcpconfig.Definition
		why, fix string
	}{
		{"a bridge written by hand", wrapped("sh", `npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer $JIRA"`),
			"npx would get JIRA in its command line (line 1), where other programs and security logs can read it.",
			"Let mcp-remote fill it in from its environment instead: npx -y mcp-remote ... --header 'Authorization: Bearer ${JIRA}'"},
		{"a script in another", wrapped("sh", `exec sh -c "GITHUB_PERSONAL_ACCESS_TOKEN=$JIRA exec github-mcp-server stdio"`),
			"sh would get JIRA in its command line (line 1), where other programs and security logs can read it.",
			`Let sh read "$JIRA" from its environment instead: sh -c '... "$JIRA" ...'`},
		{"a script keyward run cannot read", wrapped("zsh", `for x (a b) print $x; PD="$PD_KEY" exec some-mcp`),
			"keyward run cannot read the script zsh -c runs, to check where its values go: line 1: `for foo` must be followed by `in`, `do`, `;`, or a newline",
			"Write it in sh syntax for sh -c, which keyward run can read."},
		{"its own script, as wrap would change it", mcpconfig.Definition{Command: "sh", Args: []string{"-c", `exec some-mcp --token "${PD_KEY}"`}},
			"some-mcp would get PD_KEY in its command line (line 1), where other programs and security logs can read it.",
			"Pass it to some-mcp in an environment variable it reads instead."},
		{"its arguments, as wrap would write them", mcpconfig.Definition{Command: "npx", Args: []string{"-y", "slack-mcp", "--token", "${PD_KEY}"}}, "", ""},
	} {
		findings := mcpconfig.Check(load(t, "server", tc.def), refs)
		if len(findings) != 1 {
			t.Fatalf("%s: findings = %+v", tc.shape, findings)
		}
		var want []mcpconfig.Reason
		if tc.why != "" {
			want = []mcpconfig.Reason{{Why: tc.why, Fix: tc.fix}}
		}
		if got := findings[0].Reasons; !slices.Equal(got, want) {
			t.Errorf("%s: reasons = %q\nwant %q", tc.shape, got, want)
		}
	}
}

// A server keyward run refuses whose --only also leaves out a reference is one
// finding, not two, so it is counted once and wrap changes it once, with both
// fixes: the reference added to --only, and the option once the user allows it.
func TestARefusedServerThatAlsoLeavesOutAReferenceIsReportedOnce(t *testing.T) {
	def := mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", `exec npx -y slack-mcp --token "$GITHUB_TOKEN"`},
		Env: map[string]string{"GITHUB_TOKEN": "cap://github-token", "PD_KEY": "cap://pagerduty-key"}}
	everything := func(mcpconfig.Server, []string) bool { return true }
	for allowed, findings := range map[bool][]mcpconfig.Finding{
		false: mcpconfig.Check(load(t, "slack", def), refs),
		true:  mcpconfig.CheckAllowing(load(t, "slack", def), refs, everything),
	} {
		if len(findings) != 1 {
			t.Fatalf("allowed %v: findings = %+v", allowed, findings)
		}
		f := findings[0]
		if !f.Refused || strings.Join(f.CommandLine, ",") != "GITHUB_TOKEN" || strings.Join(f.Unresolved, ",") != "PD_KEY" || f.AllowCommandLine != allowed {
			t.Errorf("allowed %v: finding = %+v", allowed, f)
		}
		if want := slices.Contains(f.Want.Args, "--allow-command-line"); !slices.Contains(f.Want.Args, "GITHUB_TOKEN,PD_KEY") || want != allowed || started(t, f.Want) != allowed {
			t.Errorf("allowed %v: applied args = %q", allowed, f.Want.Args)
		}
	}
}

// keyward run refuses to start a server that would put a secret in a program's
// command line, from its URL or as another argument, unless given
// --allow-command-line. A change gives a server the option only if the user
// allows those secrets, or if its keyward run has it already, and a server that
// already runs through keyward, with nothing else to change, gets it as a change
// of its own. A server that needs none is never given it.
func TestAChangeGivesKeywardRunAllowCommandLineOnlyIfAllowed(t *testing.T) {
	keyedBridge := bridge(`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" ` + authHeader + ` --transport http-only`)
	config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"slack":  map[string]any{"command": "npx", "args": []string{"-y", "slack-mcp", "--token", "${GITHUB_TOKEN}"}},
		"keyed":  map[string]any{"type": "http", "url": "https://mcp.example.com/mcp?key=${PD_KEY}", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
		"github": map[string]any{"type": "http", "url": "https://api.example.com/mcp/", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
		"bridge": map[string]any{"command": keyedBridge.Command, "args": keyedBridge.Args, "env": keyedBridge.Env},
		"args": map[string]any{"command": "keyward", "args": []string{"run", "--only", "PD_KEY", "--", "printf", "[%s]", "--token", "${GITHUB_TOKEN}"},
			"env": map[string]string{"PD_KEY": "cap://pagerduty-key"}},
		"only": map[string]any{"command": "keyward", "args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec tool --token "$OTHER_KEY"`},
			"env": map[string]string{"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), string(config))
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]struct{ commandLine, args string }{
		"slack":  {"GITHUB_TOKEN", `run --allow-command-line --only GITHUB_TOKEN -- sh -c exec npx -y slack-mcp --token "$GITHUB_TOKEN"`},
		"keyed":  {"PD_KEY", `run --allow-command-line --only GITHUB_TOKEN,PD_KEY -- sh -c exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" ` + authHeader + ` --transport http-only`},
		"github": {"", `run --only GITHUB_TOKEN -- sh -c exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` --transport http-only`},
		"bridge": {"PD_KEY", `run --allow-command-line --only GITHUB_TOKEN,PD_KEY -- sh -c exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" ` + authHeader + ` --transport http-only`},
		"args":   {"GITHUB_TOKEN", `run --allow-command-line --only GITHUB_TOKEN,PD_KEY -- sh -c exec printf "[%s]" --token "$GITHUB_TOKEN"`},
		"only":   {"OTHER_KEY", `run --allow-command-line --only PD_KEY,OTHER_KEY -- sh -c exec tool --token "$OTHER_KEY"`},
	}
	everything := func(mcpconfig.Server, []string) bool { return true }
	for _, allowed := range []bool{false, true} {
		findings := mcpconfig.Check(servers, refs)
		if allowed {
			findings = mcpconfig.CheckAllowing(servers, refs, everything)
		}
		if len(findings) != len(want) {
			t.Fatalf("allowed %v: findings = %+v", allowed, findings)
		}
		for _, f := range findings {
			w := want[f.Name]
			if strings.Join(f.CommandLine, ",") != w.commandLine || f.AllowCommandLine != (allowed && w.commandLine != "") {
				t.Errorf("allowed %v, %s: in a command line %v, allowed %v", allowed, f.Name, f.CommandLine, f.AllowCommandLine)
			}
			args := w.args
			if !allowed {
				args = strings.Replace(args, "run --allow-command-line ", "run ", 1)
			}
			if f.Name == "bridge" && !allowed {
				// Wrapping it again would change nothing.
				args = ""
			}
			if got := strings.Join(f.Want.Args, " "); got != args {
				t.Errorf("allowed %v, %s: applied args = %q\nwant %q", allowed, f.Name, got, args)
			}
			if args != "" && started(t, f.Want) != (allowed || w.commandLine == "") {
				t.Errorf("allowed %v, %s: keyward run would start it: %v", allowed, f.Name, !allowed)
			}
		}
	}
	// A change that only adds the option says so, and a server that has it keeps it.
	f := mcpconfig.CheckAllowing(load(t, "bridge", keyedBridge), refs, everything)
	if len(f) != 1 || f[0].Suggestion != `In args, add "--allow-command-line" after "run".` || !strings.HasPrefix(f[0].Note, "Make this change to the \"bridge\" entry in ") {
		t.Fatalf("findings = %+v", f)
	}
	for _, again := range [][]mcpconfig.Finding{mcpconfig.Check(load(t, "bridge", f[0].Want), refs), mcpconfig.CheckAllowing(load(t, "bridge", f[0].Want), refs, everything)} {
		if len(again) != 1 || again[0].Suggestion != "" || !again[0].AllowCommandLine || !strings.Contains(again[0].Note, "--allow-command-line") {
			t.Errorf("once applied, findings = %+v", again)
		}
	}
	rewrapped := mcpconfig.Check(load(t, "args", mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--allow-command-line", "--only", "PD_KEY", "--", "printf", "[%s]", "--token", "${GITHUB_TOKEN}"},
		Env: map[string]string{"PD_KEY": "cap://pagerduty-key"}}), refs)
	if len(rewrapped) != 1 || !rewrapped[0].AllowCommandLine || !started(t, rewrapped[0].Want) {
		t.Errorf("with the option, findings = %+v", rewrapped)
	}
}

// keyward run refuses to start a server whose script would put a value it
// resolves in a program's command line, unless given --allow-command-line. For
// each shape of server that wrap writes, or wrote in an earlier version, Check
// reports exactly those keyward run refuses, and wrap's change for each starts,
// or puts a secret in a command line, which only the user can allow. So does
// the change for each kind of server wrap starts from. internal/shell judges
// each as keyward run does, so wrap, keyward mcp and doctor cannot drift from it.
func TestKeywardRunStartsWhatWrapWrites(t *testing.T) {
	const (
		api   = "exec npx -y mcp-remote https://api.example.com/mcp/ "
		jira  = "exec npx -y mcp-remote https://mcp.example.com/v1/mcp "
		keyed = `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" `
	)
	gh, pd, jiraEnv := map[string]string{"GITHUB_TOKEN": "cap://github-token"}, map[string]string{"PD_KEY": "cap://pagerduty-key"}, map[string]string{"JIRA": "cap://jira-token"}
	both := map[string]string{"GITHUB_TOKEN": "cap://github-token", "PD_KEY": "cap://pagerduty-key"}
	run := func(only string, env map[string]string, command ...string) mcpconfig.Definition {
		args := []string{"run"}
		if only != "" {
			args = append(args, "--only", only)
		}
		return mcpconfig.Definition{Command: "keyward", Args: slices.Concat(args, []string{"--"}, command), Env: env}
	}
	allowed := func(def mcpconfig.Definition) mcpconfig.Definition {
		def.Args = slices.Insert(slices.Clone(def.Args), 1, "--allow-command-line")
		return def
	}
	everything := func(mcpconfig.Server, []string) bool { return true }
	// changes checks wrap's change for servers: as Check suggests it, which keyward
	// run starts unless it puts a secret in a command line the user has not
	// allowed, and as CheckAllowing does once the user allows that.
	changes := func(shape string, servers []mcpconfig.Server) {
		t.Helper()
		for _, f := range mcpconfig.Check(servers, refs) {
			if f.Want.Command != "" && started(t, f.Want) != (len(f.CommandLine) == 0 || f.AllowCommandLine) {
				t.Errorf("%s: keyward run would start %q: %v, but it puts %v in a command line", shape, f.Want.Args, !started(t, f.Want), f.CommandLine)
			}
		}
		for _, f := range mcpconfig.CheckAllowing(servers, refs, everything) {
			if f.Want.Command != "" && !started(t, f.Want) {
				t.Errorf("%s: keyward run would refuse %q, allowed", shape, f.Want.Args)
			}
		}
	}
	for _, tc := range []struct {
		shape  string
		def    mcpconfig.Definition
		starts bool
	}{
		// What wrap writes, since 1.2.0.
		{"a bridge", run("GITHUB_TOKEN", gh, "sh", "-c", api+authHeader+" --transport http-only"), true},
		{"an SSE bridge", run("GITHUB_TOKEN", gh, "sh", "-c", api+authHeader+" --transport sse-only"), true},
		{"a server's own mcp-remote", run("GITHUB_TOKEN", gh, "sh", "-c", api+authHeader), true},
		{"one given a callback port", run("GITHUB_TOKEN", gh, "sh", "-c", api+"3334 "+authHeader), true},
		{"a header's text moved to env", run("GITHUB_TOKEN", map[string]string{"GITHUB_TOKEN": "cap://github-token", "KW_HDR_1": "fake-literal-team"},
			"sh", "-c", api+authHeader+` --header "X-Team: "'$''{KW_HDR_1}'"" --transport http-only`), true},
		{"a header's text stored", run("GITHUB_TOKEN,KW_HDR_1", map[string]string{"GITHUB_TOKEN": "cap://github-token", "KW_HDR_1": "cap://x-team"},
			"sh", "-c", api+authHeader+` --header "X-Team: "'$''{KW_HDR_1}'"" --transport http-only`), true},
		{"a Codex header", run("JIRA", jiraEnv, "sh", "-c", jira+`--header "Authorization: "'$''{JIRA}'"" --transport http-only`), true},
		{"a server's own script, rewritten in place", run("JIRA", jiraEnv, "sh", "-c", "cd / && "+jira+`--header 'Authorization: Bearer $''{JIRA}'`), true},
		{"a token for the server's environment", run("GITHUB_TOKEN", gh, "sh", "-c", `GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN" exec github-mcp-server stdio`), true},
		{"a key on stdin", run("PD_KEY", pd, "bash", "-c", `printf '%s' "$PD_KEY" | exec some-mcp --key-stdin`), true},
		{"a script that names no secret", run("GITHUB_TOKEN", gh, "sh", "-c", `exec some-mcp --token "$(cat ~/.token)"`), true},
		{"a token in the environment alone", run("PD_KEY", pd, "uvx", "pagerduty-mcp"), true},
		{"docker given a variable's name", run("GITHUB_TOKEN", gh, "docker", "run", "-i", "--rm", "-e", "GITHUB_TOKEN", "img"), true},
		{"a key in the URL, allowed", allowed(run("GITHUB_TOKEN,PD_KEY", both, "sh", "-c", keyed+authHeader+" --transport http-only")), true},
		{"a token as an argument, allowed", allowed(run("GITHUB_TOKEN", gh, "sh", "-c", `exec npx -y slack-mcp --token "$GITHUB_TOKEN"`)), true},
		{"a key in the URL, allowed before 1.5.0", run("GITHUB_TOKEN,PD_KEY", both, "sh", "-c", keyed+authHeader+" --transport http-only"), false},
		{"a token as an argument", run("GITHUB_TOKEN", gh, "sh", "-c", `exec npx -y slack-mcp --token "$GITHUB_TOKEN"`), false},
		{"a key in an option", run("PD_KEY", pd, "sh", "-c", `exec tool "--api-key=$PD_KEY"`), false},
		{"exec printf, the program", run("GITHUB_TOKEN", gh, "sh", "-c", `exec printf "[%s]" --token "$GITHUB_TOKEN"`), false},
		// What earlier versions wrote.
		{"a bridge of 1.0.0 and 1.0.1", run("", gh, "sh", "-c", api+`--header "Authorization: Bearer $GITHUB_TOKEN" --transport http-only`), false},
		{"a bridge of 1.0.2 to 1.1.3", run("GITHUB_TOKEN", gh, "sh", "-c", api+`--header "Authorization: Bearer $GITHUB_TOKEN" --transport http-only`), false},
		{"one with a header's text written out", run("GITHUB_TOKEN", gh, "sh", "-c",
			api+`--header "Authorization: Bearer $GITHUB_TOKEN" --header "X-Team: fake-literal-team" --transport http-only`), false},
		{"a server's own mcp-remote of 1.1.4 to 1.1.7", run("JIRA", jiraEnv, "sh", "-c", jira+`--header "Authorization: Bearer $JIRA"`), false},
		{"a key in the URL, wrapped before 1.2.0", run("PD_KEY", pd, "sh", "-c", keyed+"--transport http-only"), false},
		{"a server's own script in another, passing a token", run("GITHUB_TOKEN", gh, "sh", "-c", `exec sh -c "exec some-mcp --token \"$GITHUB_TOKEN\""`), false},
		{"one setting a token", run("GITHUB_TOKEN", gh, "sh", "-c", `exec sh -c "GITHUB_PERSONAL_ACCESS_TOKEN=$GITHUB_TOKEN exec github-mcp-server stdio"`), false},
		{"one piping a key", run("PD_KEY", pd, "sh", "-c", `exec bash -c "printf '%s' \"$PD_KEY\" | exec some-mcp --key-stdin"`), false},
		{"a bridge written by hand", run("T", map[string]string{"T": "cap://t"}, "sh", "-c", `npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer $T"`), false},
	} {
		if got := started(t, tc.def); got != tc.starts {
			t.Errorf("%s: keyward run would start it: %v, want %v", tc.shape, got, tc.starts)
		}
		servers := load(t, "server", tc.def)
		if refused := slices.ContainsFunc(mcpconfig.Check(servers, refs), func(f mcpconfig.Finding) bool { return f.Refused }); refused == tc.starts {
			t.Errorf("%s: reported as refused: %v, want %v", tc.shape, refused, !tc.starts)
		}
		changes(tc.shape, servers)
	}
	for shape, server := range map[string]map[string]any{
		"a remote server":                     {"type": "http", "url": "https://api.example.com/mcp/", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
		"an SSE server":                       {"type": "sse", "url": "https://api.example.com/sse", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
		"one with a key in its URL":           {"type": "http", "url": "https://mcp.example.com/mcp?key=${PD_KEY}"},
		"one with a header written out":       {"type": "http", "url": "https://api.example.com/mcp/", "headers": map[string]string{"X-Team-Token": "fake-literal-team"}, "env": gh},
		"a stdio server":                      {"command": "uvx", "args": []string{"pagerduty-mcp"}, "env": map[string]string{"PD_KEY": "${PD_KEY}"}},
		"one taking its token as an argument": {"command": "npx", "args": []string{"-y", "slack-mcp", "--token", "${GITHUB_TOKEN}"}},
		"one setting a token in a script":     {"command": "sh", "args": []string{"-c", `GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN" exec github-mcp-server stdio`}},
		"one piping a key in a script":        {"command": "bash", "args": []string{"-c", `printf '%s' "$PD_KEY" | exec some-mcp --key-stdin`}},
		"one passing a token in a script":     {"command": "sh", "args": []string{"-c", `exec some-mcp --token "${GITHUB_TOKEN}"`}},
		"its own mcp-remote":                  {"command": "npx", "args": []string{"-y", "mcp-remote", "https://mcp.example.com/v1/mcp", "--header", "Authorization: Bearer ${JIRA}"}},
		"its own mcp-remote with a key":       {"command": "npx", "args": []string{"-y", "mcp-remote", "https://mcp.example.com/mcp?key=${PD_KEY}", "--header", "Authorization: Bearer ${JIRA}"}},
		"docker":                              {"command": "docker", "args": []string{"run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "img"}, "env": map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}},
	} {
		config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"server": server}})
		if err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		write(t, filepath.Join(home, ".claude.json"), string(config))
		servers, errs := mcpconfig.Load(home, t.TempDir())
		if len(errs) != 0 {
			t.Fatal(errs)
		}
		if findings := mcpconfig.Check(servers, refs); len(findings) != 1 || findings[0].Want.Command != "keyward" {
			t.Errorf("%s: findings = %+v, want it wrapped", shape, findings)
		}
		changes(shape, servers)
	}
}

// started reports whether keyward run would start def, as Claude Code starts it,
// in an environment that holds refs' references: whether it is given
// --allow-command-line, or the command it starts puts no value it resolves in a
// program's command line, as internal/shell finds them.
func started(t *testing.T, def mcpconfig.Definition) bool {
	t.Helper()
	args, only, allow := def.Args[1:], []string(nil), false
	for len(args) > 0 && strings.HasPrefix(args[0], "--") && args[0] != "--" {
		switch value, inline := strings.CutPrefix(args[0], "--only="); {
		case args[0] == "--allow-command-line":
			allow = true
		case inline:
			only = append(only, strings.Split(value, ",")...)
		case args[0] == "--only":
			only, args = append(only, strings.Split(args[1], ",")...), args[1:]
		}
		args = args[1:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	var env []string
	for v, ref := range refs {
		env = append(env, v+"=cap://"+ref)
	}
	for k, v := range def.Env {
		env = slices.DeleteFunc(env, func(e string) bool { return strings.HasPrefix(e, k+"=") })
		env = append(env, k+"="+v)
	}
	name, script, ok := shell.Command(args)
	if allow || !ok {
		return true
	}
	found, err := shell.Check(name, script, resolve.Variables(env, only))
	return err == nil && len(found) == 0
}

// Once wrapped in the current form, a server is not reported again.
func TestACurrentBridgeIsNotReported(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"team": {"type": "http", "url": "https://mcp.example.com/mcp/", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}", "X-Team": "fake-literal-header"}}}}`)
	servers, _ := mcpconfig.Load(home, t.TempDir())
	team := mcpconfig.Check(servers, refs)
	if len(team) != 1 {
		t.Fatalf("findings = %+v", team)
	}
	for _, f := range []mcpconfig.Finding{team[0], finding(t, "Claude Code", "github")} {
		if findings := mcpconfig.Check(load(t, f.Name, f.Want), refs); len(findings) != 0 {
			t.Errorf("%s wrapped is reported again: %+v", f.Name, findings)
		}
	}
}

// keyward run passes on each reference its --only leaves out as it is, so a server
// that runs through keyward is reported for one in its env: written there, filled
// in by its client, or passed through by Codex. The fix adds each to --only, and
// leaves nothing to report. It is printed as the changes it makes, so that a
// server's other settings, which keyward does not read, stay as they are, and no
// literal is printed. Codex passes an env_vars variable only when it has one, and
// keyward run stops on an --only name that is not set, so a reference there moves
// into env, and env_vars keeps its other names.
func TestAWrappedServerIsReportedForAReferenceItsOnlyLeavesOut(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "pagerduty": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp", "--token", "`+argToken+`"],
      "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key", "LEVEL": "fake-literal-env"}},
    "filled": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "OTHER": "${GITHUB_TOKEN}"}}
  }}`)
	codex := write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.pagerduty]
command = "keyward"
args = ["run", "--only=PD_KEY", "--", "uvx", "pagerduty-mcp"]
cwd = "/Users/someone/work"
env = { PD_KEY = "cap://pagerduty-key", OTHER_KEY = "cap://other-key" }
env_vars = ["GITHUB_TOKEN", "EDITOR"]
startup_timeout_sec = 60
tool_timeout_sec = 300
enabled_tools = ["list_incidents"]
`)
	cursor := write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"gh": {"type": "stdio", "command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "npx", "gh-mcp"],
    "env": {"PD_KEY": "cap://pagerduty-key", "GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}, "envFile": "${workspaceFolder}/.env.mcp"}}}`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]struct{ unresolved, args, change, where string }{
		"Claude Code pagerduty": {"OTHER_KEY", "run --only PD_KEY,OTHER_KEY -- uvx pagerduty-mcp --token " + argToken,
			`In args, change "PD_KEY" to "PD_KEY,OTHER_KEY".`, `the "pagerduty" entry in ` + filepath.Join(home, ".claude.json")},
		"Claude Code filled": {"OTHER", "run --only PD_KEY,OTHER -- uvx x", `In args, change "PD_KEY" to "PD_KEY,OTHER".`, `the "filled" entry in ` + filepath.Join(home, ".claude.json")},
		"Codex pagerduty": {"GITHUB_TOKEN,OTHER_KEY", "run --only=PD_KEY,GITHUB_TOKEN,OTHER_KEY -- uvx pagerduty-mcp",
			`In args, change "--only=PD_KEY" to "--only=PD_KEY,GITHUB_TOKEN,OTHER_KEY".` + "\n" + `In env, add GITHUB_TOKEN = "cap://github-token".` + "\n" + `In env_vars, remove "GITHUB_TOKEN".`,
			"the [mcp_servers.pagerduty] table in " + codex},
		"Cursor gh": {"GITHUB_TOKEN", "run --only PD_KEY,GITHUB_TOKEN -- npx gh-mcp", `In args, change "PD_KEY" to "PD_KEY,GITHUB_TOKEN".`, `the "gh" entry in ` + cursor},
	}
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != len(want) {
		t.Fatalf("findings = %+v", findings)
	}
	for _, f := range findings {
		name := f.Client + " " + f.Name
		w := want[name]
		if strings.Join(f.Unresolved, ",") != w.unresolved || strings.Join(f.Want.Args, " ") != w.args || len(f.Exposed) != 0 {
			t.Errorf("%s: unresolved = %v, exposed = %v, applied args = %q", name, f.Unresolved, f.Exposed, f.Want.Args)
		}
		env := maps.Clone(f.Env)
		if f.Client == "Codex" {
			env["GITHUB_TOKEN"] = "cap://github-token"
		}
		if f.Want.Command != f.Command || !maps.Equal(f.Want.Env, env) {
			t.Errorf("%s: applied %+v, want only --only changed, and env for Codex", name, f.Want)
		}
		these := "this change"
		if strings.Contains(w.change, "\n") {
			these = "these changes"
		}
		if f.Suggestion != w.change || f.Note != "Make "+these+" to "+w.where+", and leave the rest of it as it is." {
			t.Errorf("%s: suggestion %q, note %q", name, f.Suggestion, f.Note)
		}
		if strings.Contains(f.Suggestion+f.Note, "fake-literal") || strings.Contains(f.Suggestion+f.Note, argToken) {
			t.Errorf("%s printed a literal:\n%s\n%s", name, f.Suggestion, f.Note)
		}
		if f.Client == "Claude Code" {
			if again := mcpconfig.Check(load(t, f.Name, f.Want), refs); len(again) != 0 {
				t.Errorf("%s is reported again once applied: %+v", name, again)
			}
		}
	}
	// Codex's and Cursor's are made by hand, from what is printed.
	for _, path := range []string{codex, cursor} {
		data, _ := os.ReadFile(path)
		edited := string(data)
		for _, f := range findings {
			if strings.HasPrefix(want[f.Client+" "+f.Name].where, "the [mcp_servers.") == (path == codex) && f.Client != "Claude Code" {
				edited = applyChange(t, edited, f.Suggestion)
			}
		}
		rel, _ := filepath.Rel(home, path)
		changed := t.TempDir()
		write(t, filepath.Join(changed, rel), edited)
		back, errs := mcpconfig.Load(changed, t.TempDir())
		if len(errs) != 0 || len(back) != 1 {
			t.Fatalf("%s read back as %+v, %v:\n%s", path, back, errs, edited)
		}
		if again := mcpconfig.Check(back, refs); len(again) != 0 {
			t.Errorf("%s is reported again once changed: %+v", path, again)
		}
		if path == codex && (back[0].Env["GITHUB_TOKEN"] != "cap://github-token" || strings.Join(back[0].PassEnv, ",") != "EDITOR") {
			t.Errorf("Codex's server read back as %+v", back[0])
		}
	}
}

// applyChange makes the changes keyward mcp prints for a server that runs through
// keyward, as a user would, in the config's text.
func applyChange(t *testing.T, config, changes string) string {
	t.Helper()
	const words = `"(?:[^"\\]|\\.)*"(?:, "(?:[^"\\]|\\.)*")*`
	for _, change := range strings.Split(changes, "\n") {
		var old, next string
		if m := regexp.MustCompile(`^In args, change (` + words + `) to (` + words + `)\.$`).FindStringSubmatch(change); m != nil {
			old, next = m[1], m[2]
			// The value of an --only is named alone.
			if strings.Contains(config, `"--only", `+old) {
				old, next = `"--only", `+old, `"--only", `+next
			}
		} else if m := regexp.MustCompile(`^In env, add (.*)\.$`).FindStringSubmatch(change); m != nil {
			old, next = " }\n", ", "+m[1]+" }\n"
		} else if m := regexp.MustCompile(`^In env_vars, remove ("[^"]*")\.$`).FindStringSubmatch(change); m != nil {
			old, next = m[1]+", ", ""
		} else {
			t.Fatalf("not a change keyward prints: %q", change)
		}
		if !strings.Contains(config, old) {
			t.Fatalf("%s is not in the config:\n%s", old, config)
		}
		config = strings.Replace(config, old, next, 1)
	}
	return config
}

// keyward run without --only resolves every reference, so it needs no change, nor
// does one whose --only names every reference in its env. A literal, a variable
// that holds no reference, and a placeholder the client does not fill in hand it
// none: Codex fills no placeholder in env. A server that is turned off starts
// nothing.
func TestAWrappedServerThatResolvesEveryReferenceItGetsIsNotReported(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "all": {"command": "keyward", "args": ["run", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key"}},
    "named": {"command": "keyward", "args": ["run", "--only", "OTHER_KEY,PD_KEY", "--", "uvx", "x"],
      "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key", "LEVEL": "info", "HOST": "${DB_HOST}"}},
    "inherited": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "x"]}
  }}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.pd]
command = "keyward"
args = ["run", "--only=PD_KEY", "--", "uvx", "x"]
env = { PD_KEY = "cap://pagerduty-key", GITHUB = "${GITHUB_TOKEN}" }
env_vars = ["EDITOR"]

[mcp_servers.off]
command = "keyward"
args = ["run", "--only", "PD_KEY", "--", "uvx", "x"]
env = { PD_KEY = "cap://pagerduty-key", OTHER_KEY = "cap://other-key" }
enabled = false
`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 || len(servers) != 5 {
		t.Fatalf("servers = %+v, errors = %v", servers, errs)
	}
	if findings := mcpconfig.Check(servers, refs); len(findings) != 0 {
		t.Errorf("findings = %+v", findings)
	}
}

// A client fills ${VAR} in a server's command and args before keyward run starts,
// and keyward run resolves only its environment, so a server that runs through
// keyward gets a reference it reads there as cap://NAME, or nothing: one migrated
// in a shell file, or one in its env. Adding it to --only would not reach the
// argument, so the server is wrapped again through sh, which fills it in from the
// resolved environment. It is then in printf's command line, which only the
// server could change. keyward run's options are read as it reads them, every
// --only included. A placeholder that reads no reference needs nothing.
func TestAWrappedServerThatReadsAReferenceInItsArgsIsWrappedAgain(t *testing.T) {
	home := t.TempDir()
	config := write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "migrated": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "printf", "[%s]", "--token", "${GITHUB_TOKEN}"], "env": {"PD_KEY": "cap://pagerduty-key"}},
    "held": {"command": "keyward", "args": ["run", "--only", "PD_KEY,OWN_TOKEN", "--", "printf", "[%s]", "--token", "${OWN_TOKEN}"], "env": {"PD_KEY": "cap://pagerduty-key", "OWN_TOKEN": "cap://github-token"}},
    "twice": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--only", "JIRA", "--", "printf", "[%s]", "--token", "${GITHUB_TOKEN}"], "env": {"PD_KEY": "cap://pagerduty-key", "JIRA": "cap://jira-token"}},
    "home": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "printf", "[%s]", "--root", "${HOME}"], "env": {"PD_KEY": "cap://pagerduty-key"}}
  }}`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	const (
		command   = `In args, change "printf", "[%s]", "--token", "${GITHUB_TOKEN}" to "sh", "-c", "exec printf \"[%s]\" --token \"$GITHUB_TOKEN\"".`
		reference = `In env, add "GITHUB_TOKEN": "cap://github-token".`
	)
	want := map[string]struct{ inArgs, args, changes string }{
		"migrated": {"GITHUB_TOKEN", `run --only GITHUB_TOKEN,PD_KEY -- sh -c exec printf "[%s]" --token "$GITHUB_TOKEN"`,
			`In args, change "PD_KEY" to "GITHUB_TOKEN,PD_KEY".` + "\n" + command + "\n" + reference},
		"held": {"OWN_TOKEN", `run --only PD_KEY,OWN_TOKEN -- sh -c exec printf "[%s]" --token "$OWN_TOKEN"`,
			`In args, change "printf", "[%s]", "--token", "${OWN_TOKEN}" to "sh", "-c", "exec printf \"[%s]\" --token \"$OWN_TOKEN\"".`},
		"twice": {"GITHUB_TOKEN", `run --only GITHUB_TOKEN,PD_KEY --only JIRA -- sh -c exec printf "[%s]" --token "$GITHUB_TOKEN"`,
			`In args, change "PD_KEY" to "GITHUB_TOKEN,PD_KEY".` + "\n" + command + "\n" + reference},
	}
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != len(want) {
		t.Fatalf("findings = %+v", findings)
	}
	for _, f := range findings {
		w := want[f.Name]
		configured := servers[slices.IndexFunc(servers, func(s mcpconfig.Server) bool { return s.Name == f.Name })]
		if strings.Join(f.InArgs, ",") != w.inArgs || strings.Join(f.Want.Args, " ") != w.args || f.Want.Command != configured.Command || len(f.Unresolved) != 0 ||
			strings.Join(f.CommandLine, ",") != w.inArgs {
			t.Errorf("%s: in args = %v, unresolved = %v, in a command line %v, applied %s %q", f.Name, f.InArgs, f.Unresolved, f.CommandLine, f.Want.Command, f.Want.Args)
			continue
		}
		// It is printed as the changes it makes, so the rest of the entry stays.
		if f.Suggestion != w.changes || !strings.HasPrefix(f.Note, "Make ") || !strings.HasSuffix(f.Note, ` to the "`+f.Name+`" entry in `+config+", and leave the rest of it as it is.") {
			t.Errorf("%s: suggestion:\n%s\nnote: %s", f.Name, f.Suggestion, f.Note)
		}
		// Started with its references resolved, the server gets the value.
		cmd := exec.Command("sh", "-c", f.Want.Args[len(f.Want.Args)-1])
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		for k, v := range f.Want.Env {
			if name, ok := strings.CutPrefix(v, "cap://"); ok {
				v = secrets[name]
			}
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		if out, err := cmd.Output(); err != nil || string(out) != "[--token][fake-github-value]" {
			t.Errorf("%s: printf got %q, %v", f.Name, out, err)
		}
		if again := mcpconfig.Check(load(t, f.Name, f.Want), refs); !settled(again) {
			t.Errorf("%s is reported again once applied: %+v", f.Name, again)
		}
	}
}

// The fix for a wrapped Codex server that reads a reference in its arguments is
// printed as the changes it makes, as the --only fix is, so settings keyward does
// not read, such as cwd and enabled_tools, stay, as do EDITOR in env_vars and a
// reference there that --only names. Made by hand, the changes leave a server
// keyward reports for nothing but the token in echo's command line.
func TestTheArgsFixKeepsACodexServersOtherSettings(t *testing.T) {
	original := `[mcp_servers.echo]
command = "keyward"
args = ["run", "--only", "PD_KEY", "--only=JIRA", "--", "/bin/echo", "--token", "${GITHUB_TOKEN}"]
cwd = "/Users/someone/work"
env = { PD_KEY = "cap://pagerduty-key" }
env_vars = ["GITHUB_TOKEN", "JIRA", "EDITOR"]
tool_timeout_sec = 300
enabled_tools = ["echo"]
`
	config := write(t, filepath.Join(t.TempDir(), ".codex", "config.toml"), original)
	servers, errs := mcpconfig.Load(filepath.Dir(filepath.Dir(config)), t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	f := findings[0]
	changes := `In args, change "PD_KEY" to "GITHUB_TOKEN,PD_KEY".` + "\n" +
		`In args, change "/bin/echo", "--token", "${GITHUB_TOKEN}" to "sh", "-c", "exec /bin/echo --token \"$GITHUB_TOKEN\"".` + "\n" +
		`In env, add GITHUB_TOKEN = "cap://github-token".` + "\n" + `In env_vars, remove "GITHUB_TOKEN".`
	if f.Suggestion != changes || f.Note != "Make these changes to the [mcp_servers.echo] table in "+config+", and leave the rest of it as it is." {
		t.Errorf("suggestion:\n%s\nnote: %s", f.Suggestion, f.Note)
	}
	if got := strings.Join(f.Want.Args, " "); got != `run --only GITHUB_TOKEN,PD_KEY --only=JIRA -- sh -c exec /bin/echo --token "$GITHUB_TOKEN"` {
		t.Errorf("applied args = %s", got)
	}
	edited := applyChange(t, original, f.Suggestion)
	changed := t.TempDir()
	write(t, filepath.Join(changed, ".codex", "config.toml"), edited)
	back, errs := mcpconfig.Load(changed, t.TempDir())
	if len(errs) != 0 || len(back) != 1 {
		t.Fatalf("read back as %+v, %v:\n%s", back, errs, edited)
	}
	if again := mcpconfig.Check(back, refs); !settled(again) {
		t.Errorf("reported again once changed: %+v", again)
	}
	if !slices.Equal(back[0].Args, f.Want.Args) || back[0].Env["GITHUB_TOKEN"] != "cap://github-token" || strings.Join(back[0].PassEnv, ",") != "JIRA,EDITOR" {
		t.Errorf("read back as %+v", back[0])
	}
	for _, kept := range []string{`cwd = "/Users/someone/work"`, "tool_timeout_sec = 300", `enabled_tools = ["echo"]`} {
		if !strings.Contains(edited, kept) {
			t.Errorf("the changes lost %s:\n%s", kept, edited)
		}
	}
}

// A script run with sh -c is rewritten in place, never run in another sh -c, whose
// sh would expand each value into the script and so into the command lines of the
// programs it starts. Each placeholder that reads a reference is written so that
// it is filled in after keyward run resolves it: by sh, as "$VAR", or, in a header
// mcp-remote is given, by mcp-remote, spelled as in keyward's bridge. That holds
// for a server wrapped for the first time, one wrapped again, and an mcp-remote
// started directly. A placeholder that reads no reference is left for the client.
func TestAScriptIsRewrittenInPlaceRatherThanRunInAnotherScript(t *testing.T) {
	const remote = "[-y][mcp-remote][https://mcp.example.com/v1/mcp][--header][Authorization: Bearer ${JIRA}]"
	jira := map[string]string{"JIRA": "cap://jira-token"}
	for _, tc := range []struct {
		name            string
		def             mcpconfig.Definition
		script, started string
		inURL           string
	}{
		{"a bridge whose URL reads a placeholder", bridge(`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=${PD_KEY}" ` + authHeader + ` --transport http-only`),
			`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" ` + authHeader + ` --transport http-only`,
			"[-y][mcp-remote][https://mcp.example.com/mcp?key=fake-pagerduty-value][--header][Authorization: Bearer ${GITHUB_TOKEN}][--transport][http-only]", "PD_KEY"},
		{"a bridge written by hand", mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA", "--", "sh", "-c",
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer "'${JIRA}'""`}, Env: jira},
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer "'$''{JIRA}'""`, remote, ""},
		{"mcp-remote started directly", mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA", "--", "npx", "-y", "mcp-remote",
			"https://mcp.example.com/v1/mcp", "--header", "Authorization: Bearer ${JIRA}"}, Env: jira},
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer "'$''{JIRA}'""`, remote, ""},
		{"a server's own script", mcpconfig.Definition{Command: "sh", Args: []string{"-c", `exec printf '[%s]' --token "${GITHUB_TOKEN}" --home "${HOME}"`}},
			`exec printf '[%s]' --token "$GITHUB_TOKEN" --home "${HOME}"`, "[--token][fake-github-value][--home][/home/someone]", ""},
		{"each kind of quoting", mcpconfig.Definition{Command: "bash", Args: []string{"-lc", `exec printf '[%s]' '--a=${GITHUB_TOKEN}' --b=${GITHUB_TOKEN} "${GITHUB_TOKEN}suffix"`}},
			`exec printf '[%s]' '--a='"$GITHUB_TOKEN"'' --b="$GITHUB_TOKEN" "$GITHUB_TOKEN""suffix"`,
			"[--a=fake-github-value][--b=fake-github-value][fake-github-valuesuffix]", ""},
		{"a header in single quotes", mcpconfig.Definition{Command: "sh", Args: []string{"-c", `cd / && exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header 'Authorization: Bearer ${JIRA}'`}},
			`cd / && exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header 'Authorization: Bearer $''{JIRA}'`, remote, ""},
		{"a shell given an option's name", mcpconfig.Definition{Command: "bash", Args: []string{"-o", "pipefail", "-c", `exec printf '[%s]' "${GITHUB_TOKEN}"`}},
			`exec printf '[%s]' "$GITHUB_TOKEN"`, "[fake-github-value]", ""},
		{"a shell given a shopt option", mcpconfig.Definition{Command: "bash", Args: []string{"-O", "extglob", "-c", `exec printf '[%s]' "${GITHUB_TOKEN}"`}},
			`exec printf '[%s]' "$GITHUB_TOKEN"`, "[fake-github-value]", ""},
		{"a shell given an rc file", mcpconfig.Definition{Command: "bash", Args: []string{"--rcfile", "/dev/null", "-c",
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer ${JIRA}"`}},
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer "'$''{JIRA}'""`, remote, ""},
		{"a wrapped shell given a shopt option", mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "JIRA", "--", "bash", "+O", "extglob", "-c",
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer ${JIRA}"`}, Env: jira},
			`exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer "'$''{JIRA}'""`, remote, ""},
		{"a variable for the program's environment", mcpconfig.Definition{Command: "sh", Args: []string{"-c", `API_KEY="${GITHUB_TOKEN}" exec printenv API_KEY`}},
			`API_KEY="$GITHUB_TOKEN" exec printenv API_KEY`, "fake-github-value\n", ""},
		{"a shell that programs keeping the environment start", mcpconfig.Definition{Command: "nohup", Args: []string{"nice", "-n", "5", "env", "LEVEL=debug", "sh", "-c", `exec printf '[%s]' "${GITHUB_TOKEN}"`}},
			`exec printf '[%s]' "$GITHUB_TOKEN"`, "[fake-github-value]", ""},
	} {
		findings := mcpconfig.Check(load(t, "tool", tc.def), refs)
		if len(findings) != 1 {
			t.Errorf("%s: findings = %+v", tc.name, findings)
			continue
		}
		f := findings[0]
		at := slices.Index(f.Want.Args, "--")
		shells := []string{"sh -c", "bash -lc", "bash -o pipefail -c", "bash -O extglob -c", "bash --rcfile /dev/null -c", "bash +O extglob -c", "nohup nice -n 5 env LEVEL=debug sh -c"}
		if at < 0 || f.Want.Command != "keyward" || !slices.Contains(shells, strings.Join(f.Want.Args[at+1:len(f.Want.Args)-1], " ")) {
			t.Errorf("%s: applied %s %q", tc.name, f.Want.Command, f.Want.Args)
			continue
		}
		if got := f.Want.Args[len(f.Want.Args)-1]; got != tc.script {
			t.Errorf("%s: script = %s\nwant %s", tc.name, got, tc.script)
		}
		if strings.Join(f.InURL, ",") != tc.inURL || len(f.Exposed) != 0 {
			t.Errorf("%s: in URL = %v, exposed = %v", tc.name, f.InURL, f.Exposed)
		}
		def := f.Want
		def.Env = maps.Clone(def.Env)
		def.Env["HOME"] = "/home/someone"
		if got := mcpRemoteArgs(t, def); got != tc.started {
			t.Errorf("%s: started with %s\nwant %s", tc.name, got, tc.started)
		}
	}
}

// A server's script that has sh expand a migrated variable, as "$VAR", reads the
// reference its client inherited, so it is reported and wrapped with the variable
// in --only and env, its script as it is. One in single quotes, or one that holds
// no reference, is read by no one.
func TestAScriptThatExpandsAMigratedVariableIsWrapped(t *testing.T) {
	for script, vars := range map[string]string{
		`GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN" exec printenv GITHUB_PERSONAL_ACCESS_TOKEN`: "GITHUB_TOKEN",
		`GITHUB_PERSONAL_ACCESS_TOKEN=$GITHUB_TOKEN exec printenv GITHUB_PERSONAL_ACCESS_TOKEN`:   "GITHUB_TOKEN",
		`echo '$GITHUB_TOKEN' >&2; exec printenv HOME`:                                            "",
		`ROOT="$HOME" exec printenv ROOT`:                                                         "",
	} {
		findings := mcpconfig.Check(load(t, "gh", mcpconfig.Definition{Command: "sh", Args: []string{"-c", script}}), refs)
		if vars == "" {
			if len(findings) != 0 {
				t.Errorf("%s: findings = %+v", script, findings)
			}
			continue
		}
		if len(findings) != 1 {
			t.Errorf("%s: findings = %+v", script, findings)
			continue
		}
		f := findings[0]
		if strings.Join(f.Vars, ",") != vars || strings.Join(f.Want.Args, " ") != "run --only "+vars+" -- sh -c "+script || f.Want.Env[vars] != "cap://"+refs[vars] {
			t.Errorf("%s: vars = %v, applied %q with env %v", script, f.Vars, f.Want.Args, f.Want.Env)
		}
		if got := mcpRemoteArgs(t, f.Want); got != secrets[refs[vars]]+"\n" {
			t.Errorf("%s: the server got %q", script, got)
		}
		if again := mcpconfig.Check(load(t, "gh", f.Want), refs); len(again) != 0 {
			t.Errorf("%s: reported again once applied: %+v", script, again)
		}
	}
}

// A script keyward cannot read safely, as one with a command substitution or an
// escaped placeholder, a placeholder in an argument sh gives the script, or one
// given after an option keyward does not know, is reported with no change to
// make, and a note to change it by hand. So is one where a value written for sh
// to fill in could still reach a command line unseen: in another shell's script,
// or, in a script that runs mcp-remote, anywhere but its URL and headers, as in a
// variable that one of them reads. So is one a shell runs in an environment that
// may lack the variable, as one that env -i or docker run starts. One that needs
// no rewrite is wrapped as it is.
func TestAScriptThatCannotBeRewrittenSafelyIsLeftToTheUser(t *testing.T) {
	for _, args := range [][]string{
		{"sh", "-c", `exec some-mcp --token "$(cat /dev/null)${GITHUB_TOKEN}"`},
		{"sh", "-c", "exec some-mcp --token `echo ${GITHUB_TOKEN}`"},
		{"sh", "-c", `exec some-mcp --token \${GITHUB_TOKEN}`},
		{"sh", "-c", `exec some-mcp --token "$1"`, "_", "${GITHUB_TOKEN}"},
		{"sh", "-c", "cat <<EOF | some-mcp\n${GITHUB_TOKEN}\nEOF"},
		{"ksh", "-R", "xref.db", "-c", `exec some-mcp --token "${GITHUB_TOKEN}"`},
		{"sh", "-c", `H="Authorization: Bearer ${GITHUB_TOKEN}"; exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "$H"`},
		{"sh", "-c", `U="https://mcp.example.com/v1/mcp?key=${GITHUB_TOKEN}"; exec npx -y mcp-remote "$U"`},
		{"sh", "-c", `exec sh -c 'exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer ${GITHUB_TOKEN}"'`},
		{"bash", "-lc", `exec bash -O extglob -c 'exec some-mcp --token "${GITHUB_TOKEN}"'`},
		{"env", "-i", "sh", "-c", `exec /bin/echo "token=${GITHUB_TOKEN}"`},
		{"env", "-u", "GITHUB_TOKEN", "sh", "-c", `exec /bin/echo "token=${GITHUB_TOKEN}"`},
		{"env", "-", "sh", "-c", `exec /bin/echo "token=${GITHUB_TOKEN}"`},
		{"docker", "run", "-i", "--rm", "img", "sh", "-c", `exec some-mcp --token "${GITHUB_TOKEN}"`},
		{"kubectl", "exec", "-i", "pod", "--", "sh", "-c", `exec some-mcp --token "${GITHUB_TOKEN}"`},
		{"sudo", "-u", "svc", "sh", "-c", `exec some-mcp --token "${GITHUB_TOKEN}"`},
	} {
		findings := mcpconfig.Check(load(t, "tool", mcpconfig.Definition{Command: args[0], Args: args[1:]}), refs)
		if len(findings) != 1 {
			t.Errorf("%q: findings = %+v", args, findings)
			continue
		}
		if f := findings[0]; !f.ByHand || f.Suggestion != "" || f.Want.Command != "" || !strings.Contains(f.Note, "by hand") || strings.Join(f.Vars, ",") != "GITHUB_TOKEN" {
			t.Errorf("%q: finding = %+v", args, f)
		}
	}
	script := `exec some-mcp --token "$(cat ~/.token)"`
	findings := mcpconfig.Check(load(t, "tool", mcpconfig.Definition{Command: "sh", Args: []string{"-c", script}, Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}), refs)
	if len(findings) != 1 || findings[0].ByHand || strings.Join(findings[0].Want.Args, " ") != "run --only GITHUB_TOKEN -- sh -c "+script {
		t.Errorf("findings = %+v", findings)
	}
}

// wrap moves a header's literal text into a KW_HDR variable, which doctor says to
// store and replace with a reference. The bridge then puts nothing in a command
// line, but mcp-remote would send the reference unless its --only names it. A
// bridge that exposes a secret is wrapped again instead, which names it too.
func TestABridgeIsReportedForAReferenceItsOnlyLeavesOut(t *testing.T) {
	const apiKey = `--header "X-Api-Key: "'$''{KW_HDR_1}'""`
	for _, tc := range []struct{ script, unresolved, exposed, args string }{
		{`exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` ` + apiKey + ` --transport http-only`, "KW_HDR_1", "",
			`run --only GITHUB_TOKEN,KW_HDR_1 -- sh -c exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` ` + apiKey + ` --transport http-only`},
		{`exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer $GITHUB_TOKEN" ` + apiKey + ` --transport http-only`, "", "GITHUB_TOKEN",
			`run --only GITHUB_TOKEN,KW_HDR_1 -- sh -c exec npx -y mcp-remote https://api.example.com/mcp/ ` + authHeader + ` ` + apiKey + ` --transport http-only`},
	} {
		findings := mcpconfig.Check(load(t, "api", mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", tc.script},
			Env: map[string]string{"GITHUB_TOKEN": "cap://github-token", "KW_HDR_1": "cap://x-api-key"}}), refs)
		if len(findings) != 1 {
			t.Fatalf("findings for %s = %+v", tc.script, findings)
		}
		f := findings[0]
		if strings.Join(f.Unresolved, ",") != tc.unresolved || strings.Join(f.Exposed, ",") != tc.exposed || strings.Join(f.Want.Args, " ") != tc.args {
			t.Errorf("unresolved = %v, exposed = %v, applied args = %q", f.Unresolved, f.Exposed, f.Want.Args)
		}
		if again := mcpconfig.Check(load(t, "api", f.Want), refs); len(again) != 0 {
			t.Errorf("reported again once applied: %+v", again)
		}
	}
}

// The generated shell command must hand the program exactly the intended arguments.
func TestTheShellCommandExpandsToTheOriginalArguments(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"probe": {"command": "printf", "args": ["[%s]", "Authorization: Bearer ${GITHUB_TOKEN}", "a \"quoted\" $literal", "${GITHUB_TOKEN}suffix", ""]}}}`)
	servers, _ := mcpconfig.Load(home, t.TempDir())
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != 1 {
		t.Fatalf("findings = %v", findings)
	}
	s := parseJSON(t, findings[0])
	cmd := exec.Command("sh", "-c", s.Args[len(s.Args)-1])
	cmd.Env = []string{"GITHUB_TOKEN=resolved-value", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := `[Authorization: Bearer resolved-value][a "quoted" $literal][resolved-valuesuffix][]`; string(out) != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestCodexSuggestionsAreTOMLThatReadsBack(t *testing.T) {
	f := finding(t, "Codex", "atlassian-cloud")
	if !strings.Contains(f.Suggestion, `[mcp_servers."atlassian-cloud"]`) || !strings.Contains(f.Note, `[mcp_servers."atlassian-cloud".env_http_headers]`) {
		t.Errorf("suggestion or note does not name the tables:\n%s\n%s", f.Suggestion, f.Note)
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), f.Suggestion)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 || len(servers) != 1 {
		t.Fatalf("suggestion did not read back: %v %v\n%s", servers, errs, f.Suggestion)
	}
	if s := servers[0]; s.Command != "keyward" || s.Env["JIRA"] != "cap://jira-token" || len(mcpconfig.Check(servers, refs)) != 0 {
		t.Errorf("read back = %+v", s)
	}
}

func TestCodexKeepsTheStartupTimeout(t *testing.T) {
	if f := finding(t, "Codex", "pagerduty"); !strings.Contains(f.Suggestion, "startup_timeout_sec = 60") {
		t.Errorf("suggestion lost the timeout:\n%s", f.Suggestion)
	}
}

// The table that wrap and unwrap print for a Codex server replaces the server's,
// so it keeps every key keyward does not change, as cwd and the tool settings are,
// and each env_vars name that holds no reference. A value there that may be a
// secret, as a header written in a key Codex does not read, is hidden. Replaced
// by hand, wrapped and unwrapped, the server keeps them all.
func TestACodexTableKeepsTheSettingsKeywardDoesNotChange(t *testing.T) {
	const kept = `cwd = "/Users/someone/dev"
disabled_tools = ["delete_repo"]
enabled_tools = ["get_issue"]
startup_timeout_sec = 20
tool_timeout_sec = 90
`
	const tools = "\n[mcp_servers.github.tools.get_issue]\napproval_mode = \"approve\"\n"
	for _, table := range []string{
		"[mcp_servers.github]\ncommand = \"github-mcp-server\"\nargs = [\"stdio\"]\nenv_vars = [\"GITHUB_TOKEN\", \"HTTPS_PROXY\"]\n" + kept,
		"[mcp_servers.github]\nurl = \"https://api.example.com/mcp/\"\nbearer_token_env_var = \"GITHUB_TOKEN\"\n" + kept,
	} {
		home := t.TempDir()
		config := write(t, filepath.Join(home, ".codex", "config.toml"), table+`headers = { Authorization = "Bearer `+headerToken+`" }`+"\n"+tools)
		servers, errs := mcpconfig.Load(home, t.TempDir())
		if len(errs) != 0 {
			t.Fatal(errs)
		}
		wrap := mcpconfig.Check(servers, refs)
		if len(wrap) != 1 {
			t.Fatalf("findings = %+v", wrap)
		}
		for _, f := range []mcpconfig.Finding{wrap[0]} {
			if strings.Contains(f.Suggestion, headerToken) || !strings.Contains(f.Note, "Copy each hidden value from the current definition") {
				t.Errorf("printed the header, or no note says to copy it:\n%s\n%s", f.Suggestion, f.Note)
			}
		}
		// The user replaces the table, with the hidden value copied in.
		write(t, config, strings.Replace(wrap[0].Suggestion, `"Bearer <41 bytes hidden>"`, `"Bearer `+headerToken+`"`, 1)+tools)
		wrapped, errs := mcpconfig.Load(home, t.TempDir())
		if len(errs) != 0 || len(wrapped) != 1 || len(mcpconfig.Check(wrapped, refs)) != 0 {
			t.Fatalf("read back as %+v, %v:\n%s", wrapped, errs, wrap[0].Suggestion)
		}
		unwrap := mcpconfig.Undo(wrapped)
		if len(unwrap) != 1 {
			t.Fatalf("undo = %+v", unwrap)
		}
		for name, f := range map[string]mcpconfig.Finding{"wrap": wrap[0], "unwrap": unwrap[0]} {
			for _, line := range strings.Split(strings.TrimSpace(kept), "\n") {
				if !strings.Contains(f.Suggestion, line+"\n") {
					t.Errorf("%s lost %s:\n%s", name, line, f.Suggestion)
				}
			}
		}
		if strings.Contains(table, "env_vars") {
			if !strings.Contains(wrap[0].Suggestion, `env_vars = ["HTTPS_PROXY"]`) || !strings.Contains(unwrap[0].Suggestion, `env_vars = ["HTTPS_PROXY", "GITHUB_TOKEN"]`) {
				t.Errorf("env_vars after wrap:\n%s\nafter unwrap:\n%s", wrap[0].Suggestion, unwrap[0].Suggestion)
			}
		}
	}
}

func TestAnUnreadableConfigIsReportedNotGuessed(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), "{not json")
	write(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.x]\ncommand = \"unterminated\n")
	if _, errs := mcpconfig.Load(home, t.TempDir()); len(errs) != 2 {
		t.Errorf("errors = %v, want one per unreadable file", errs)
	}
}

// A suggestion writes env inline, and TOML lets no table be defined twice, so the
// notes of wrap and unwrap both say to delete a server's [env] subtable as well,
// one of a bridge that wrap writes again included.
func TestCodexNotesSayToDeleteTheEnvSubtable(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.pd]
command = "uvx"

[mcp_servers.pd.env]
PD_KEY = "${PD_KEY}"

[mcp_servers.pd.tools.search]
approval_mode = "approve"

[mcp_servers.wrapped]
command = "keyward"
args = ["run", "--only", "PD_KEY", "--", "uvx", "pd-mcp"]

[mcp_servers.wrapped.env]
PD_KEY = "cap://pagerduty-key"

[mcp_servers.bridge]
command = "keyward"
args = ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/ --header \"Authorization: Bearer $GITHUB_TOKEN\""]

[mcp_servers.bridge.env]
GITHUB_TOKEN = "cap://github-token"
`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	wrap, unwrap := mcpconfig.Check(servers, refs), mcpconfig.Undo(servers)
	if len(wrap) != 2 || len(unwrap) != 2 {
		t.Fatalf("wrap = %+v, unwrap = %+v", wrap, unwrap)
	}
	for _, f := range append(wrap, unwrap...) {
		if want := " and delete its [mcp_servers." + f.Name + ".env] table. Other subtables, such as tools, can stay."; !strings.Contains(f.Note, want) || !strings.Contains(f.Suggestion, "\nenv = {") {
			t.Errorf("%s: note lacks %q, or the suggestion has no inline env:\n%s\n%s", f.Name, want, f.Suggestion, f.Note)
		}
	}
}

func TestCodexUnicodeEscapesAreDecoded(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.x]\ncommand = \"caf\\u00e9\"\n")
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 || len(servers) != 1 || servers[0].Command != "café" {
		t.Errorf("servers = %+v, errors = %v", servers, errs)
	}
}

func wrapped(t *testing.T) []mcpconfig.Server {
	t.Helper()
	home, workdir := t.TempDir(), t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "pagerduty": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key", "LEVEL": "info"}},
    "github": {"command": "keyward", "args": ["run", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/ --header \"Authorization: Bearer $GITHUB_TOKEN\" --transport http-only"], "env": {"GITHUB_TOKEN": "cap://github-token"}},
    "aws": {"command": "uvx", "args": ["aws-mcp"]}
  }}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.pagerduty]
command = "/opt/homebrew/bin/keyward"
args = ["run", "--only=PD_KEY", "--", "uvx", "pagerduty-mcp"]
env = { PD_KEY = "cap://pagerduty-key", LEVEL = "info" }
startup_timeout_sec = 60
`)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"gh": {"command": "keyward", "args": ["run", "--", "npx", "gh-mcp"], "env": {"GITHUB_TOKEN": "cap://github-token"}}}}`)
	servers, errs := mcpconfig.Load(home, workdir)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	return servers
}

func undone(t *testing.T, client, name string) mcpconfig.Finding {
	t.Helper()
	for _, f := range mcpconfig.Undo(wrapped(t)) {
		if f.Client == client && f.Name == name {
			return f
		}
	}
	t.Fatalf("no undo for %s/%s", client, name)
	return mcpconfig.Finding{}
}

// Undo lists only servers that start through keyward, each with the definition
// that starts it without keyward, reading its secrets from the environment again.
func TestUndoStartsEachServerWithoutKeyward(t *testing.T) {
	if n := len(mcpconfig.Undo(wrapped(t))); n != 4 {
		t.Errorf("Undo found %d servers, want the 4 that start through keyward", n)
	}
	f := undone(t, "Claude Code", "pagerduty")
	s := parseJSON(t, f)
	if s.Command != "uvx" || strings.Join(s.Args, " ") != "pagerduty-mcp" {
		t.Errorf("command = %s %v", s.Command, s.Args)
	}
	if s.Env["PD_KEY"] != "${PD_KEY}" || s.Env["LEVEL"] != "<4 bytes hidden>" || f.Want.Env["LEVEL"] != "info" {
		t.Errorf("printed env = %v, applied env = %v", s.Env, f.Want.Env)
	}
	if !strings.Contains(f.Note, "hidden value") {
		t.Errorf("note does not say where the hidden value comes from: %s", f.Note)
	}
	if strings.Join(f.Vars, ",") != "PD_KEY" {
		t.Errorf("vars = %v", f.Vars)
	}
}

// A server wrapped by hand may turn off keyward run's output masking.
func TestUndoReadsAServerWrappedWithNoMask(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--no-mask", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"},
		{"run", "--only=PD_KEY", "--no-mask", "uvx", "pagerduty-mcp"},
	} {
		def := mcpconfig.Definition{Command: "keyward", Args: args, Env: map[string]string{"PD_KEY": "cap://pagerduty-key"}}
		findings := mcpconfig.Undo(load(t, "pagerduty", def))
		if len(findings) != 1 {
			t.Fatalf("%v: findings = %+v", args, findings)
		}
		if s := parseJSON(t, findings[0]); s.Command != "uvx" || strings.Join(s.Args, " ") != "pagerduty-mcp" {
			t.Errorf("%v: command = %s %v", args, s.Command, s.Args)
		}
	}
}

// keyward mcp wrap --allow-command-line gives a server's keyward run that option,
// so unwrap and uninstall must read past it.
func TestUndoReadsAServerWrappedWithAllowCommandLine(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--allow-command-line", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"},
		{"run", "--only=PD_KEY", "--no-mask", "--allow-command-line", "uvx", "pagerduty-mcp"},
	} {
		def := mcpconfig.Definition{Command: "keyward", Args: args, Env: map[string]string{"PD_KEY": "cap://pagerduty-key"}}
		findings := mcpconfig.Undo(load(t, "pagerduty", def))
		if len(findings) != 1 {
			t.Fatalf("%v: findings = %+v", args, findings)
		}
		if s := parseJSON(t, findings[0]); s.Command != "uvx" || strings.Join(s.Args, " ") != "pagerduty-mcp" {
			t.Errorf("%v: command = %s %v", args, s.Command, s.Args)
		}
	}
}

// keyward run reads --allow-command-line among its --only options, and so does
// Check, as it does --no-mask, and it reads a bridge behind them as keyward's.
// Written again, the bridge puts nothing in a command line, so needs no option.
func TestCheckReadsTheOnlyOfAServerWrappedWithAllowCommandLine(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "before": {"command": "keyward", "args": ["run", "--allow-command-line", "--no-mask", "--only", "PD_KEY", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key"}},
    "between": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--allow-command-line", "--only", "JIRA", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "JIRA": "cap://jira-token"}},
    "bridge": {"command": "keyward", "args": ["run", "--allow-command-line", "--only", "PD_KEY", "--", "sh", "-c", "exec npx -y mcp-remote https://mcp.example.com/mcp --header \"Authorization: Bearer $PD_KEY\" --transport http-only"], "env": {"PD_KEY": "cap://pagerduty-key"}}
  }}`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]string{
		"before": "run --allow-command-line --no-mask --only PD_KEY,OTHER_KEY -- uvx x",
		"bridge": `run --only PD_KEY -- sh -c exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer "'$''{PD_KEY}'"" --transport http-only`,
	}
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != len(want) {
		t.Fatalf("findings = %+v", findings)
	}
	for _, f := range findings {
		if got := strings.Join(f.Want.Args, " "); got != want[f.Name] {
			t.Errorf("%s: applied args = %q, want %q", f.Name, got, want[f.Name])
		}
		if again := mcpconfig.Check(load(t, f.Name, f.Want), refs); len(again) != 0 {
			t.Errorf("%s is reported again once applied: %+v", f.Name, again)
		}
	}
}

// keyward run reads --no-mask among its --only options, and so does Check: a
// reference that a server's --only leaves out, or that it reads in its args,
// is added to its first --only, and one a later --only names is not reported.
func TestCheckReadsTheOnlyOfAServerWrappedWithNoMask(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "before": {"command": "keyward", "args": ["run", "--no-mask", "--only", "PD_KEY", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key"}},
    "inline": {"command": "keyward", "args": ["run", "--no-mask", "--only=PD_KEY", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key"}},
    "between": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--no-mask", "--only", "JIRA", "--", "uvx", "x"], "env": {"PD_KEY": "cap://pagerduty-key", "JIRA": "cap://jira-token"}},
    "args": {"command": "keyward", "args": ["run", "--no-mask", "--only", "PD_KEY", "--", "printf", "[%s]", "--token", "${GITHUB_TOKEN}"], "env": {"PD_KEY": "cap://pagerduty-key"}}
  }}`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]string{
		"before": "run --no-mask --only PD_KEY,OTHER_KEY -- uvx x",
		"inline": "run --no-mask --only=PD_KEY,OTHER_KEY -- uvx x",
		"args":   `run --no-mask --only GITHUB_TOKEN,PD_KEY -- sh -c exec printf "[%s]" --token "$GITHUB_TOKEN"`,
	}
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != len(want) {
		t.Fatalf("findings = %+v", findings)
	}
	for _, f := range findings {
		if got := strings.Join(f.Want.Args, " "); got != want[f.Name] {
			t.Errorf("%s: applied args = %q, want %q", f.Name, got, want[f.Name])
		}
		if again := mcpconfig.Check(load(t, f.Name, f.Want), refs); !settled(again) {
			t.Errorf("%s is reported again once applied: %+v", f.Name, again)
		}
	}
}

// settled reports whether Check, run on a server once its change is applied,
// finds nothing more to change in it, but at most a secret it puts in a command
// line, which only the server can take out.
func settled(findings []mcpconfig.Finding) bool {
	return !slices.ContainsFunc(findings, func(f mcpconfig.Finding) bool { return f.Suggestion != "" || f.ByHand || len(f.CommandLine) == 0 })
}

// The mcp-remote bridge needs no keyward: sh fills the header from the environment.
func TestUndoKeepsTheShellBridgeForARemoteServer(t *testing.T) {
	s := parseJSON(t, undone(t, "Claude Code", "github"))
	if s.Command != "sh" || len(s.Args) != 2 || s.Args[0] != "-c" || !strings.Contains(s.Args[1], "mcp-remote") {
		t.Errorf("command = %s %v", s.Command, s.Args)
	}
	if s.Env["GITHUB_TOKEN"] != "${GITHUB_TOKEN}" {
		t.Errorf("env = %v", s.Env)
	}
}

func TestUndoUsesCursorsPlaceholderSyntax(t *testing.T) {
	if s := parseJSON(t, undone(t, "Cursor", "gh")); s.Env["GITHUB_TOKEN"] != "${env:GITHUB_TOKEN}" || s.Command != "npx" {
		t.Errorf("undo = %+v", s)
	}
}

// Undo prints a wrapped server's arguments as wrap does, each argument in a script
// included, and applies them as they are.
func TestUndoPrintsSecretsInArgumentsOnlyAsTheirLength(t *testing.T) {
	refEnv := map[string]string{"PD_KEY": "cap://pagerduty-key"}
	for _, tc := range []struct {
		def            mcpconfig.Definition
		printed, field string
	}{
		{mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "PD_KEY", "--", "uvx", "tool-mcp", "--token", argToken}, Env: refEnv},
			`"<41 bytes hidden>"`, "args[7]"},
		{mcpconfig.Definition{Command: "keyward", Args: []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec uvx tool-mcp --token ` + argToken + ` --key "$PD_KEY"`}, Env: refEnv},
			`exec uvx tool-mcp --token <41 bytes hidden> --key \"$PD_KEY\"`, "args[6]"},
		{bridge(`exec npx -y mcp-remote "https://bot:` + urlPassword + `@mcp.example.com/mcp?api_key=` + queryKey + `&key=$PD_KEY" --header "X-Api-Key: ` + headerToken + `" --header "Authorization: Bearer $GITHUB_TOKEN"`),
			`exec npx -y mcp-remote \"https://<3 bytes hidden>:<15 bytes hidden>@mcp.example.com/mcp?api_key=<38 bytes hidden>&key=$PD_KEY\" --header \"X-Api-Key: <41 bytes hidden>\" --header \"Authorization: Bearer $GITHUB_TOKEN\"`, "args[6]"},
	} {
		findings := mcpconfig.Undo(load(t, "tool", tc.def))
		if len(findings) != 1 {
			t.Fatalf("findings = %+v", findings)
		}
		f := findings[0]
		for _, value := range []string{argToken, urlPassword, queryKey, headerToken} {
			if strings.Contains(f.Suggestion+f.Note, value) {
				t.Errorf("printed %q:\n%s\n%s", value, f.Suggestion, f.Note)
			}
		}
		if !strings.Contains(f.Suggestion, tc.printed) || !strings.Contains(f.Note, "the hidden text in args is from its "+tc.field+".") {
			t.Errorf("suggestion lacks %s, or note %s:\n%s\n%s", tc.printed, tc.field, f.Suggestion, f.Note)
		}
		if !slices.Equal(f.Want.Args, tc.def.Args[5:]) {
			t.Errorf("applied args = %q, want %q", f.Want.Args, tc.def.Args[5:])
		}
	}
}

// A bridge from an earlier keyward holds its headers' text in its script, where
// only a header's name marks it as a credential, as doctor reports it. unwrap's
// suggestion, and keyward mcp's once the bridge is unwrapped, print that text only
// as its length, keeping each header's auth scheme and placeholders, and apply it
// as it is.
func TestAnEarlierBridgesHeaderTextIsPrintedOnlyAsItsLength(t *testing.T) {
	script := `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Token ` + opaqueToken + `" --header "X-Api-Key: ` + namedValue +
		`" --header "X-Team: fake-\"literal\""'$''{PD_KEY}'"" --transport http-only`
	const printed = `--header \"Authorization: Token <25 bytes hidden>\" --header \"X-Api-Key: <33 bytes hidden>\" --header \"X-Team: <16 bytes hidden>\"'$''{PD_KEY}'\"\" --transport http-only`
	undo := mcpconfig.Undo(load(t, "team", bridge(script)))
	if len(undo) != 1 {
		t.Fatalf("findings = %+v", undo)
	}
	again := mcpconfig.Check(load(t, "team", undo[0].Want), refs)
	if len(again) != 1 {
		t.Fatalf("findings once unwrapped = %+v", again)
	}
	for _, tc := range []struct {
		f     mcpconfig.Finding
		field string
	}{{undo[0], "args[6]"}, {again[0], "args[1]"}} {
		for _, value := range []string{opaqueToken, namedValue, "fake-"} {
			if strings.Contains(tc.f.Suggestion+tc.f.Note, value) {
				t.Errorf("printed %q:\n%s\n%s", value, tc.f.Suggestion, tc.f.Note)
			}
		}
		if !strings.Contains(tc.f.Suggestion, printed) || !strings.HasSuffix(tc.f.Note, "the hidden text in args is from its "+tc.field+".") {
			t.Errorf("suggestion lacks %s, or note %s:\n%s\n%s", printed, tc.field, tc.f.Suggestion, tc.f.Note)
		}
		if tc.f.Want.Args[len(tc.f.Want.Args)-1] != script {
			t.Errorf("applied args = %q", tc.f.Want.Args)
		}
	}
}

// Codex does not expand placeholders in env, so secrets pass through env_vars.
func TestUndoForCodexPassesTheVariablesThrough(t *testing.T) {
	f := undone(t, "Codex", "pagerduty")
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), f.Suggestion)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 || len(servers) != 1 {
		t.Fatalf("suggestion did not read back: %v\n%s", errs, f.Suggestion)
	}
	s := servers[0]
	if s.Command != "uvx" || strings.Join(s.PassEnv, ",") != "PD_KEY" || s.Env["LEVEL"] != "<4 bytes hidden>" || s.Env["PD_KEY"] != "" {
		t.Errorf("read back = %+v\n%s", s, f.Suggestion)
	}
	if f.Want.Env["LEVEL"] != "info" || !strings.Contains(f.Note, "hidden value") {
		t.Errorf("applied env = %v, note = %s", f.Want.Env, f.Note)
	}
	if !strings.Contains(f.Suggestion, "startup_timeout_sec = 60") {
		t.Errorf("lost the timeout:\n%s", f.Suggestion)
	}
}
