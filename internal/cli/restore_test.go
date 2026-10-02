package cli_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nwokolo24/keyward/internal/vault"
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

func TestRestoreUninstallStopsOnlyAfterCompleteApprovedRestoration(t *testing.T) {
	for _, scenario := range []struct {
		answer, content string
		stopped         bool
	}{
		{"yes\n", "TOKEN=cap://token\n", true},
		{"no\n", "TOKEN=cap://token\n", false},
		{"yes\n", "TOKEN=cap://token\nMISSING=cap://absent\n", false},
	} {
		path := writeFixture(t, scenario.content)
		h := newHarness(t, scenario.answer, map[string]string{"token": "dummy-value"}, nil)
		stopped := false
		h.cli.Service = func(action string) (string, error) {
			got, _ := os.ReadFile(path)
			if action != "uninstall" || string(got) != "TOKEN='dummy-value'\n" {
				t.Fatal("daemon stopped before restoration completed")
			}
			stopped = true
			return "startup removed", nil
		}
		code := h.cli.Run([]string{"service", "uninstall", "--restore", path})
		if stopped != scenario.stopped || (code == 0) != scenario.stopped {
			t.Fatalf("uninstall: stopped %t, code %d", stopped, code)
		}
	}
}

func TestRestoreUninstallDryRunCannotStopDaemon(t *testing.T) {
	path := writeFixture(t, "TOKEN=cap://token\n")
	h := newHarness(t, "yes\n", map[string]string{"token": "dummy-value"}, nil)
	h.cli.Service = func(string) (string, error) { t.Fatal("dry run stopped daemon"); return "", nil }
	if code := h.cli.Run([]string{"service", "uninstall", "--restore", "--dry-run", path}); code != 2 {
		t.Fatal("combined uninstall accepted a dry run")
	}
}
