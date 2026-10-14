package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

const wrappedServer = `{"mcpServers": {"pagerduty": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}}`

func TestMCPUndoShowsHowToStartEachServerWithoutKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(wrappedServer), 0o600)
	if code := h.cli.Run([]string{"mcp", "--undo"}); code != 1 {
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
	if code := h.cli.Run([]string{"mcp", "--undo"}); code != 0 || !strings.Contains(h.out(), "No MCP server starts through keyward") {
		t.Errorf("exit %d:\n%s", code, h.out())
	}
}
