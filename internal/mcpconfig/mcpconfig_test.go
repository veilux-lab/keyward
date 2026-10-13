package mcpconfig_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/mcpconfig"
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

func fixture(t *testing.T) (home, workdir string) {
	t.Helper()
	home, workdir = t.TempDir(), t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{
  "mcpServers": {
    "github": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}},
    "pagerduty": {"command": "uvx", "args": ["pagerduty-mcp"], "env": {"PD_KEY": "${PD_KEY}", "LEVEL": "info"}},
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

func TestALocalServerIsWrappedDirectly(t *testing.T) {
	s := parseJSON(t, finding(t, "Claude Code", "pagerduty"))
	if s.Command != "keyward" || strings.Join(s.Args, " ") != "run --only PD_KEY -- uvx pagerduty-mcp" {
		t.Errorf("command = %s %v", s.Command, s.Args)
	}
	if s.Env["PD_KEY"] != "cap://pagerduty-key" || s.Env["LEVEL"] != "info" {
		t.Errorf("env = %v", s.Env)
	}
}

// A remote server's header must be filled in after keyward resolves the value, and
// without ${} braces, which Claude Code would expand first.
func TestARemoteServerGoesThroughABridgeThatExpandsTheHeaderLate(t *testing.T) {
	s := parseJSON(t, finding(t, "Claude Code", "github"))
	if s.Command != "keyward" || len(s.Args) != 7 || s.Args[2] != "GITHUB_TOKEN" || s.Args[4] != "sh" || s.Args[5] != "-c" {
		t.Fatalf("args = %v", s.Args)
	}
	script := s.Args[6]
	if strings.Contains(script, "${") || !strings.Contains(script, "mcp-remote") || !strings.Contains(script, "https://api.example.com/mcp/") {
		t.Errorf("script = %s", script)
	}
	if s.Env["GITHUB_TOKEN"] != "cap://github-token" {
		t.Errorf("env = %v", s.Env)
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

func TestAnUnreadableConfigIsReportedNotGuessed(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), "{not json")
	write(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.x]\ncommand = \"unterminated\n")
	if _, errs := mcpconfig.Load(home, t.TempDir()); len(errs) != 2 {
		t.Errorf("errors = %v, want one per unreadable file", errs)
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
