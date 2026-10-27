package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/ledger"
)

func TestMCPShowsTheFixForEachServerThatNeedsKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"github": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}}, "aws": {"command": "uvx", "args": ["aws"]}}}`), 0o600)
	if code := h.cli.Run([]string{"mcp"}); code != 1 {
		t.Errorf("exit %d, want 1 while a server needs a change", code)
	}
	out := h.out()
	for _, want := range []string{"github", "GITHUB_TOKEN", `"command": "keyward"`, "mcp-remote", "cap://github-token", "Replace the"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "aws") {
		t.Errorf("listed a server that needs no change:\n%s", out)
	}
}

func TestMCPSaysWhenNothingNeedsAChange(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	homed(t, h)
	if code := h.cli.Run([]string{"mcp"}); code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
	if !strings.Contains(h.out(), "No MCP server needs a change") {
		t.Errorf("output:\n%s", h.out())
	}
}

func TestDoctorPointsAtMCPWhenAServerNeedsKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"gh": {"command": "gh-mcp", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}`), 0o600)
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(h.out(), "keyward mcp") {
		t.Errorf("doctor did not point at keyward mcp:\n%s", h.out())
	}
}

// A bridge from an earlier keyward is reported for what it does: it already runs
// through keyward, but its token is in mcp-remote's command line.
func TestMCPAndDoctorReportABridgeThatExposesItsToken(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"github": {"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/ --header \"Authorization: Bearer $GITHUB_TOKEN\" --transport http-only"], "env": {"GITHUB_TOKEN": "cap://github-token"}}}}`), 0o600)
	if code := h.cli.Run([]string{"mcp"}); code != 1 {
		t.Errorf("exit %d, want 1 while a server exposes a secret", code)
	}
	for _, want := range []string{"1 MCP server(s) put a secret in a command line", "exposes GITHUB_TOKEN", "'$''{GITHUB_TOKEN}'"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("mcp output lacks %q:\n%s", want, h.out())
		}
	}
	if strings.Contains(h.out(), "would receive cap://") {
		t.Errorf("mcp says the server would receive a reference:\n%s", h.out())
	}

	h = newHarness(t, "", nil, nil)
	h.cli.Home = home
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(h.out(), "put a secret in a command line, which any process can read; see keyward mcp") {
		t.Errorf("doctor output:\n%s", h.out())
	}
}

const wrappedServer = `{"mcpServers": {"pagerduty": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}}`

func TestMCPUndoShowsHowToStartEachServerWithoutKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(wrappedServer), 0o600)
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 1 {
		t.Errorf("exit %d, want 1 while a server starts through keyward", code)
	}
	for _, want := range []string{"pagerduty", "PD_KEY", `"command": "uvx"`, "${PD_KEY}", "Replace the", "keyward restore"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("output lacks %q:\n%s", want, h.out())
		}
	}
}

func TestMCPUndoSaysWhenNoServerUsesKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	homed(t, h)
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 0 || !strings.Contains(h.out(), "No MCP server starts through keyward") {
		t.Errorf("exit %d:\n%s", code, h.out())
	}
}

// fakeTools stands in for the claude CLI, editing ~/.claude.json as it would.
func fakeTools(t *testing.T, h *harness, home string) *[]string {
	t.Helper()
	var calls []string
	h.cli.LookPath = func(name string) (string, error) {
		if name == "claude" {
			return "/usr/local/bin/claude", nil
		}
		return "", os.ErrNotExist
	}
	h.cli.RunTool = func(dir string, argv ...string) ([]byte, error) {
		calls = append(calls, strings.Join(argv[1:], " "))
		if argv[2] == "--help" {
			return []byte("add-json"), nil
		}
		config := filepath.Join(home, ".claude.json")
		var doc map[string]map[string]any
		data, _ := os.ReadFile(config)
		json.Unmarshal(data, &doc)
		switch argv[2] {
		case "remove":
			delete(doc["mcpServers"], argv[3])
		case "add-json":
			var def any
			json.Unmarshal([]byte(argv[4]), &def)
			doc["mcpServers"][argv[3]] = def
		}
		out, _ := json.Marshal(doc)
		os.WriteFile(config, out, 0o600)
		return nil, nil
	}
	return &calls
}

const unwrappedServer = `{"mcpServers": {"pagerduty": {"command": "uvx", "args": ["pagerduty-mcp"], "env": {"PD_KEY": "${PD_KEY}"}}}}`

func TestMCPWrapAppliesThroughClaudeAfterYesAndUnwrapReverses(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(unwrappedServer), 0o600)
	calls := fakeTools(t, h, home)
	if code := h.cli.Run([]string{"mcp", "wrap"}); code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, h.out(), h.err())
	}
	if !strings.Contains(h.out(), "claude mcp remove pagerduty -s user") {
		t.Errorf("the commands were not shown:\n%s", h.out())
	}
	data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if !strings.Contains(string(data), "/opt/homebrew/bin/keyward") {
		t.Errorf("config after wrap: %s (calls %q)", data, *calls)
	}
	if records, _ := h.cli.Ledger.Records(); len(records) != 1 || records[0].Kind != ledger.Server || records[0].Name != "pagerduty" {
		t.Errorf("records = %+v", records)
	}

	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 0 {
		t.Fatalf("unwrap exit %d: %s", code, h.err())
	}
	data, _ = os.ReadFile(filepath.Join(home, ".claude.json"))
	if strings.Contains(string(data), "keyward") {
		t.Errorf("config after unwrap: %s", data)
	}
	if records, _ := h.cli.Ledger.Records(); len(records) != 0 {
		t.Errorf("records after unwrap = %+v", records)
	}
}

func TestMCPWrapWithoutYesChangesNothing(t *testing.T) {
	h := newHarness(t, "no\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(unwrappedServer), 0o600)
	calls := fakeTools(t, h, home)
	h.cli.Run([]string{"mcp", "wrap"})
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q without a yes", call)
		}
	}
}

// Codex and Cursor are printed: Codex's command cannot keep every setting.
func TestMCPWrapPrintsWhatItCannotApply(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.pagerduty]\ncommand = \"uvx\"\nenv_vars = [\"PD_KEY\"]\n"), 0o600)
	fakeTools(t, h, home)
	if code := h.cli.Run([]string{"mcp", "wrap"}); code != 1 {
		t.Errorf("exit %d, want 1 while a change is left to the user", code)
	}
	if !strings.Contains(h.out(), "[mcp_servers.pagerduty]") || !strings.Contains(h.out(), "Codex") {
		t.Errorf("output:\n%s", h.out())
	}
}
