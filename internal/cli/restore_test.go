package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

type restoreStore struct {
	vault.Store
	gets int
}

func (s *restoreStore) Get(name string) (vault.Secret, error) {
	s.gets++
	return s.Store.Get(name)
}

func TestRestoreOnlyWritesAfterExactYes(t *testing.T) {
	for _, answer := range []string{"yes\n", "  yes  \n", "y\n", "Yes\n", "YES\n", "yes please\n", "no\n", "\n", ""} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			original := "export TOKEN='cap://token'\n"
			path := writeFixture(t, original)
			h := newHarness(t, answer, map[string]string{"token": "dummy-restored-value"}, nil)
			s := &restoreStore{Store: h.store}
			h.cli.Store = s
			code := h.cli.Run([]string{"restore", path})
			got, _ := os.ReadFile(path)
			if strings.TrimSpace(answer) == "yes" {
				if code != 0 || string(got) != "export TOKEN='dummy-restored-value'\n" || s.gets != 1 {
					t.Fatalf("approved restore failed: code %d; stderr %s", code, h.err())
				}
			} else if code != 1 || string(got) != original || s.gets != 0 {
				t.Fatal("unapproved restore read a value or modified the file")
			}
			if !strings.Contains(h.out(), "TOKEN") || !strings.Contains(h.out(), "cap://token") || !strings.Contains(h.err(), "plaintext") || !strings.Contains(h.err(), "yes") {
				t.Fatal("restore did not list items and explain the confirmation")
			}
			if strings.Contains(h.out()+h.err(), "dummy-restored-value") {
				t.Fatal("restore output disclosed a value")
			}
		})
	}
}

type planReader struct {
	t *testing.T
	h *harness
	s *restoreStore
}

func (r planReader) Read(p []byte) (int, error) {
	if !strings.Contains(r.h.out(), "cap://token") || r.s.gets != 0 {
		r.t.Fatal("confirmation was requested before the redacted plan, or after reading a value")
	}
	return strings.NewReader("yes\n").Read(p)
}

func TestRestorePrintsPlanBeforeReadingConfirmation(t *testing.T) {
	path := writeFixture(t, "TOKEN=cap://token\n")
	h := newHarness(t, "", map[string]string{"token": "dummy-value"}, nil)
	s := &restoreStore{Store: h.store}
	h.cli.Store = s
	h.cli.Stdin = planReader{t: t, h: h, s: s}
	if code := h.cli.Run([]string{"restore", path}); code != 0 {
		t.Fatalf("restore failed: %s", h.err())
	}
}

func TestRestoreDryRunReadsNoValuesAndDoesNotPrompt(t *testing.T) {
	original := "TOKEN=cap://token\n"
	path := writeFixture(t, original)
	h := newHarness(t, "yes\n", map[string]string{"token": "dummy-value"}, nil)
	s := &restoreStore{Store: h.store}
	h.cli.Store = s
	if code := h.cli.Run([]string{"restore", "--dry-run", path}); code != 0 {
		t.Fatalf("dry run failed: %s", h.err())
	}
	got, _ := os.ReadFile(path)
	if string(got) != original || s.gets != 0 || strings.Contains(h.err(), "Enter") {
		t.Fatal("dry run prompted, read a value, or changed the file")
	}
}

func TestRestoreRejectsApprovalBypass(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"restore", "--auto-approve", "unused"}); code != 2 {
		t.Fatal("restore accepted an approval bypass")
	}
}

func TestUninstallCannotRestoreImplicitly(t *testing.T) {
	path := writeFixture(t, "TOKEN=cap://token\n")
	h := newHarness(t, "yes\n", map[string]string{"token": "dummy-value"}, nil)
	s := &restoreStore{Store: h.store}
	h.cli.Store = s
	h.cli.Service = func(string) (string, error) { t.Fatal("invalid uninstall stopped daemon"); return "", nil }
	if code := h.cli.Run([]string{"service", "uninstall", "--restore", path}); code != 2 || s.gets != 0 {
		t.Fatal("uninstall accepted implicit restoration")
	}
}

func TestUninstallWarnsBeforeStoppingAndDoesNotRestore(t *testing.T) {
	for _, answer := range []string{"yes\n", "no\n", "y\n", "Yes\n", ""} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			original := "TOKEN=cap://token\n"
			path := writeFixture(t, original)
			h := newHarness(t, answer, map[string]string{"token": "dummy-value"}, nil)
			s := &restoreStore{Store: h.store}
			h.cli.Store = s
			stopped := false
			h.cli.Service = func(action string) (string, error) {
				if action != "uninstall" || !strings.Contains(h.err(), "Warning:") || !strings.Contains(h.err(), "keyward restore ~/.zshrc .env") {
					t.Fatal("uninstall stopped before showing the restore warning")
				}
				stopped = true
				return "startup removed", nil
			}
			code := h.cli.Run([]string{"service", "uninstall"})
			approved := answer == "yes\n"
			got, _ := os.ReadFile(path)
			if stopped != approved || (code == 0) != approved || s.gets != 0 || string(got) != original {
				t.Fatal("uninstall ignored refusal or restored a file")
			}
			if !strings.Contains(h.err(), "keyward restore --dry-run") || !strings.Contains(h.err(), "cap://") {
				t.Fatal("uninstall warning omitted the preview or reference consequences")
			}
		})
	}
}

// Restoring a file leaves MCP servers on keyward; say so, and how to leave fully.
func TestRestoreNotesMCPServersThatStillStartThroughKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"pagerduty": {"command": "keyward", "args": ["run", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}}`), 0o600)
	path := migrated(t, h)
	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"restore", path}); code != 0 {
		t.Fatalf("restore: %d %s", code, h.err())
	}
	if !strings.Contains(h.out(), "1 MCP server(s) still start through keyward") || !strings.Contains(h.out(), "keyward mcp unwrap") {
		t.Errorf("restore does not mention the MCP server:\n%s", h.out())
	}
}

// restore puts each value back with the quoting migrate found, and forgets the
// file once nothing in it uses keyward.
func TestRestoreUsesTheRecordedQuotingAndForgetsTheFile(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	path := writeFixture(t, "export GITHUB_TOKEN=\"ghp_perfectlyFine0123456789\"\n")
	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"restore", path}); code != 0 {
		t.Fatalf("restore: %d %s", code, h.err())
	}
	if data, _ := os.ReadFile(path); string(data) != "export GITHUB_TOKEN=\"ghp_perfectlyFine0123456789\"\n" {
		t.Errorf("restored = %q, want the original line", data)
	}
	if records, _ := h.cli.Ledger.Records(); len(records) != 0 {
		t.Errorf("records = %+v, want the file forgotten", records)
	}
}
