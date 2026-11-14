package cli_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/exposure"
	"github.com/veilux-lab/keyward/internal/vault"
)

// flat is s with each run of white space as one space, so a test reads doctor's
// words whatever their columns and wrapping.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

// row is the first row of doctor's output that holds start, with the lines under
// it, as flat makes them.
func row(out, start string) string {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		end := i + 1
		for end < len(lines) && strings.HasPrefix(lines[end], "   ") {
			end++
		}
		if got := flat(strings.Join(lines[i:end], "\n")); strings.Contains(got+" ", start) {
			return got
		}
	}
	return ""
}

// verdict is the last paragraph of doctor's output, its verdict, as flat makes it.
func verdict(out string) string {
	paragraphs := strings.Split(strings.TrimRight(out, "\n"), "\n\n")
	return flat(paragraphs[len(paragraphs)-1])
}

// checklist is each line of doctor's checklist, as flat makes it.
func checklist(out string) []string {
	_, list, _ := strings.Cut("\n"+out, "\nkeyward doctor  ")
	list, _, _ = strings.Cut(list, "\n\n")
	var checks []string
	for _, line := range strings.Split(list, "\n") {
		switch {
		case strings.HasPrefix(line, "  ✓ ") || strings.HasPrefix(line, "  ! ") || strings.HasPrefix(line, "  ✗ "):
			checks = append(checks, flat(line))
		case len(checks) > 0:
			checks[len(checks)-1] += " " + flat(line)
		}
	}
	return checks
}

// The four checks of the report itself, as they read when each passes.
var reportPasses = []string{
	"✓ References 1 secret(s) stored and referenced",
	"✓ Known secrets none in plaintext",
	"✓ Maybe secrets nothing else looks like one",
	"✓ Unused none",
}

// doctor ends with a line for each check it ran, which says it passed, needs
// attention, or failed, and none for a check with nothing to check: the vault
// without a secret to open, the recovery code without a marker, MCP servers
// without a home, AI agents before their instructions are written, or running
// programs without the daemon. Output never starts with a blank line.
func TestDoctorsChecklist(t *testing.T) {
	const (
		reference = `{"command": "tool", "env": {"A": "${A}"}}`
		refused   = `{"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/ --header \"Authorization: Bearer $GITHUB_TOKEN\" --transport http-only"], "env": {"GITHUB_TOKEN": "cap://github-token"}}`
	)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, h *harness)
		code  int
		want  []string
		end   string
	}{
		{"each passes", func(t *testing.T, h *harness) {
			os.WriteFile(h.cli.RecoveryMarker, nil, 0o600)
			if err := agents.Default(h.cli.Home).Write(); err != nil {
				t.Fatal(err)
			}
		}, 0, append(slices.Clone(reportPasses),
			"✓ Vault opens with its key",
			"✓ Recovery a recovery code has been shown",
			"✓ Backups none from migrate",
			"✓ MCP servers keyward mcp finds nothing to change",
			"✓ AI agents each installed agent reads ~/.agents/keyward.md",
			"✓ Processes no secret in a running program's command line",
		), "✓ No problems found."},
		{"each fails or needs attention", func(t *testing.T, h *harness) {
			h.store.Seed(map[string]string{"github-token": "v"})
			h.cli.Store = unopenable{h.store}
			h.cli.Backups.Path = filepath.Join(h.cli.Home, ".zshrc")
			os.WriteFile(filepath.Join(h.cli.Home, ".claude.json"), []byte(`{"mcpServers": {"tool": `+reference+`, "github": `+refused+`}}`), 0o600)
			os.MkdirAll(filepath.Join(h.cli.Home, ".claude"), 0o755)
			if err := agents.Default(h.cli.Home).Write(); err != nil {
				t.Fatal(err)
			}
			h.cli.Exposures = func() ([]exposure.Exposure, error) { return nil, errors.New("the daemon is busy") }
		}, 1, append([]string{"✓ References 2 secret(s) stored and referenced"}, append(slices.Clone(reportPasses[1:]),
			"✗ Vault does not open: keyward.vault does not match the vault key in your Keychain; if this vault came from another Mac, run: keyward recovery restore",
			"! Recovery Save a recovery code for your vault, in case its key is ever lost: run keyward recovery show in Terminal.app. An AI agent must ask the user to run it.",
			"! Backups could not be checked",
			"✗ MCP servers 1 MCP server(s) would receive cap:// references instead of values; see keyward mcp",
			"✗ 1 MCP server(s) would put a secret in a command line, so keyward run refuses to start them; see keyward mcp",
			"! AI agents 1 installed AI agent(s) do not read ~/.agents/keyward.md; run keyward agents link",
			"! Processes could not be checked",
		)...), "✗ Problems found: the vault does not open; 1 MCP server(s) would receive cap:// references instead of values; " +
			"1 MCP server(s) would put a secret in a command line, so keyward run refuses to start them."},
		{"a secret in a command line", func(t *testing.T, h *harness) {
			os.WriteFile(h.cli.RecoveryMarker, nil, 0o600)
			h.cli.Exposures = func() ([]exposure.Exposure, error) {
				return []exposure.Exposure{{Secret: "alpha", PID: 42, Program: "node"}}, nil
			}
		}, 1, append(slices.Clone(reportPasses),
			"✓ Vault opens with its key",
			"✓ Recovery a recovery code has been shown",
			"✓ Backups none from migrate",
			"✓ MCP servers keyward mcp finds nothing to change",
			"✗ Processes 1 secret(s) in a running program's command line, listed above",
		), "✗ Problems found: 1 secret(s) in a running program's command line."},
		// The MCP line credits keyward mcp, so it stays true beside a credential
		// written in a config.
		{"a credential written in an MCP config", func(t *testing.T, h *harness) {
			os.WriteFile(h.cli.RecoveryMarker, nil, 0o600)
			os.WriteFile(filepath.Join(h.cli.Home, ".claude.json"), []byte(`{"mcpServers": {"slack": {"command": "npx", "args": ["-y", "slack-mcp", "--token", "`+leftoverToken+`"]}}}`), 0o600)
		}, 1, []string{
			"✓ References 1 secret(s) stored and referenced",
			"✗ Known secrets 1 credential(s) in plaintext, listed above",
			"✓ Maybe secrets nothing else looks like one",
			"✓ Unused none",
			"✓ Vault opens with its key",
			"✓ Recovery a recovery code has been shown",
			"✓ Backups none from migrate",
			"✓ MCP servers keyward mcp finds nothing to change",
			"✓ Processes no secret in a running program's command line",
		}, "✗ Problems found: 1 credential(s) in plaintext."},
		{"only what can be checked", func(t *testing.T, h *harness) {
			h.cli.Home, h.cli.Workdir, h.cli.RecoveryMarker, h.cli.Exposures = "", "", "", nil
			h.cli.Store = vault.NewMemory()
		}, 0, []string{
			"✓ References 0 secret(s) stored and referenced",
			"✓ Known secrets none in plaintext",
			"✓ Maybe secrets nothing else looks like one",
			"✓ Unused none",
			"✓ Backups none from migrate",
		}, "✓ No problems found."},
		{"agents without their instructions", func(t *testing.T, h *harness) {
			os.MkdirAll(filepath.Join(h.cli.Home, ".claude"), 0o755)
			h.cli.RecoveryMarker, h.cli.Exposures = "", nil
		}, 0, append(slices.Clone(reportPasses),
			"✓ Vault opens with its key",
			"✓ Backups none from migrate",
			"✓ MCP servers keyward mcp finds nothing to change",
		), "✓ No problems found."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "", map[string]string{"alpha": "v"}, nil)
			home := homed(t, h)
			os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export A='cap://alpha'\n"), 0o644)
			h.cli.RecoveryMarker = filepath.Join(t.TempDir(), "recovery-shown")
			h.cli.Exposures = func() ([]exposure.Exposure, error) { return nil, nil }
			tc.setup(t, h)

			if code := h.cli.Run([]string{"doctor"}); code != tc.code {
				t.Errorf("exit code = %d, want %d", code, tc.code)
			}
			if strings.HasPrefix(h.out(), "\n") {
				t.Errorf("the output starts with a blank line:\n%s", h.out())
			}
			if got := checklist(h.out()); !slices.Equal(got, tc.want) {
				t.Errorf("checklist:\n%s\nwant\n%s\n\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"), h.out())
			}
			if got := verdict(h.out()); got != tc.end {
				t.Errorf("verdict = %q, want %q", got, tc.end)
			}
		})
	}
}

// A check that could not run says so on stderr, as before, and needs attention
// in the checklist, which the verdict counts. An MCP config that cannot be read
// was not checked, so no line says its servers are fine.
func TestDoctorSaysWhichChecksItCouldNotRun(t *testing.T) {
	h := newHarness(t, "", map[string]string{"alpha": "v"}, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export A='cap://alpha'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"gh": {"command": "gh-mcp"}}`), 0o600)
	h.cli.Backups.Path = filepath.Join(home, ".zshrc")
	h.cli.Exposures = func() ([]exposure.Exposure, error) { return nil, errors.New("the daemon is busy") }

	if code := h.cli.Run([]string{"doctor"}); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, want := range []string{"Could not check for backups: ", "Could not read an MCP config, so it was not checked: ", "Could not check running programs for secrets: the daemon is busy"} {
		if !strings.Contains(h.err(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, h.err())
		}
	}
	if !slices.Contains(checklist(h.out()), "! MCP servers 1 MCP config(s) could not be read, so their servers were not checked") || strings.Contains(h.out(), "finds nothing to change") {
		t.Errorf("the checklist does not say the config was not checked:\n%s", h.out())
	}
	if got := verdict(h.out()); got != "✓ No problems found. 3 checks need attention." {
		t.Errorf("verdict = %q", got)
	}
}
