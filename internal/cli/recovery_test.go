package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/vault"
)

// withVault serves the harness from a real encrypted vault, so recovery has a key.
func withVault(t *testing.T, h *harness) (*vault.Encrypted, *vault.Memory) {
	t.Helper()
	keys := vault.NewMemory()
	dir := t.TempDir()
	v := &vault.Encrypted{Path: filepath.Join(dir, "test.vault"), Keys: keys}
	if err := v.Put("token", vault.NewSecret([]byte("value-1")), ""); err != nil {
		t.Fatal(err)
	}
	h.cli.Store, h.cli.Recovery = v, v
	h.cli.RecoveryMarker = v.Path + ".recovery-shown"
	return v, keys
}

func TestRecoveryShowNeedsATerminal(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	withVault(t, h)
	if code := h.cli.Run([]string{"recovery", "show"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Contains(h.out(), "KWR1-") || !strings.Contains(h.err(), "terminal") {
		t.Errorf("printed a code, or did not say why:\n%s%s", h.out(), h.err())
	}
}

func TestRecoveryShowNeedsYes(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	withVault(t, h)
	h.cli.Interactive = true
	if code := h.cli.Run([]string{"recovery", "show"}); code == 0 || strings.Contains(h.out(), "KWR1-") {
		t.Errorf("showed the code without confirmation (exit %d):\n%s", code, h.out())
	}
}

func TestRecoveryShowThenRestoreRecoversALostKey(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	v, keys := withVault(t, h)
	h.cli.Interactive = true
	if code := h.cli.Run([]string{"recovery", "show"}); code != 0 {
		t.Fatalf("show: %d %s", code, h.err())
	}
	var code string
	for _, field := range strings.Fields(h.out()) {
		if strings.HasPrefix(field, "KWR1-") {
			code = field
		}
	}
	if code == "" {
		t.Fatalf("no code in the output:\n%s", h.out())
	}
	if _, err := os.Stat(h.cli.RecoveryMarker); err != nil {
		t.Error("showing the code was not recorded, so reminders would continue")
	}

	keys.Delete("master")
	lost := &vault.Encrypted{Path: v.Path, Keys: keys}
	h.cli.Store, h.cli.Recovery = lost, lost
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(code + "\n"), nil }
	h.stdout.Reset()
	if exit := h.cli.Run([]string{"recovery", "restore"}); exit != 0 {
		t.Fatalf("restore: %d %s", exit, h.err())
	}
	if !strings.Contains(h.out(), "restored") {
		t.Errorf("restore did not report the result:\n%s", h.out())
	}
	if got, err := lost.Get("token"); err != nil || string(got.Bytes()) != "value-1" {
		t.Errorf("Get after recovery = %v", err)
	}
}

func TestRecoveryRestoreRejectsAMistypedCode(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	withVault(t, h)
	h.cli.ReadSecret = func() ([]byte, error) { return []byte("KWR1-AAAA-BBBB"), nil }
	if code := h.cli.Run([]string{"recovery", "restore"}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
}

func TestMigrateRemindsUntilARecoveryCodeIsShown(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	withVault(t, h)
	if code := h.cli.Run([]string{"migrate", writeFixture(t, rcFixture)}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	if !strings.Contains(h.out(), "keyward recovery show") {
		t.Errorf("no reminder to save a recovery code:\n%s", h.out())
	}
	os.WriteFile(h.cli.RecoveryMarker, nil, 0o600)
	h.stdout.Reset()
	h.cli.Run([]string{"doctor"})
	if strings.Contains(h.out(), "keyward recovery show") {
		t.Errorf("reminded after the code was shown:\n%s", h.out())
	}
}

// Every command the CLI records must be one the activity log accepts, or using it
// prints a logging warning.
func TestActivityLogAcceptsEveryRecordedCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log, err := activity.New(activity.Config{Dir: dir, Retention: 1 << 40, MaxBytes: 1 << 20, RotateBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"add", "ls", "rm", "run", "migrate", "restore", "backups", "agents", "recovery", "doctor", "daemon", "service", "help", "version"} {
		h := newHarness(t, "", nil, nil)
		homed(t, h)
		h.cli.Record = func(e activity.Event) {
			if err := log.Record(e); err != nil {
				t.Errorf("%s: activity log refused %+v: %v", command, e, err)
			}
		}
		h.cli.Run([]string{command, "--unknown-flag"})
	}
}
