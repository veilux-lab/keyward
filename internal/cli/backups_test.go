package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/vault"
)

func backupKeys(t *testing.T, store vault.Store) []string {
	t.Helper()
	entries, err := store.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, e := range entries {
		if backup.IsKey(e.Name) {
			keys = append(keys, e.Name)
		}
	}
	return keys
}

func migrated(t *testing.T, h *harness) string {
	t.Helper()
	path := writeFixture(t, rcFixture)
	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	h.stdout.Reset()
	h.stderr.Reset()
	return path
}

func TestBackupsListsOriginalsWithoutContents(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	path := migrated(t, h)
	if code := h.cli.Run([]string{"backups"}); code != 0 {
		t.Fatalf("backups: %d %s", code, h.err())
	}
	if !strings.Contains(h.out(), path) || !strings.Contains(h.out(), "encrypted") {
		t.Errorf("listing lacks the original or the warning:\n%s", h.out())
	}
	if strings.Contains(h.out(), token) {
		t.Error("listing printed a secret")
	}
}

func TestBackupsRemoveSelectedFilesOrAll(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	first := migrated(t, h)
	second := migrated(t, h)
	if code := h.cli.Run([]string{"backups", "rm", first}); code != 0 {
		t.Fatalf("rm: %d %s", code, h.err())
	}
	if left, _ := h.cli.Backups.List(); len(left) != 1 || left[0].Original != second {
		t.Fatalf("after removing one file's backups: %+v", left)
	}
	if code := h.cli.Run([]string{"backups", "rm", "--all"}); code != 0 {
		t.Fatalf("rm --all: %d %s", code, h.err())
	}
	if left, _ := h.cli.Backups.List(); len(left) != 0 {
		t.Fatalf("after --all: %+v", left)
	}
	if code := h.cli.Run([]string{"backups", "rm"}); code != 2 {
		t.Errorf("rm without files: code %d, want 2", code)
	}
}

func TestRestoreRemovesBackupsOfFullyRestoredFiles(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	path := migrated(t, h)
	legacy := path + ".keyward-backup-20261004T101500Z"
	if err := os.WriteFile(legacy, []byte(rcFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"restore", path}); code != 0 {
		t.Fatalf("restore: %d %s%s", code, h.out(), h.err())
	}
	if left, _ := h.cli.Backups.ForFile(path); len(left) != 0 {
		t.Errorf("backups remain after a full restore: %+v", left)
	}
	if !strings.Contains(h.out(), "Removed 2 backup(s)") {
		t.Errorf("removal not reported:\n%s", h.out())
	}
}

func TestRestoreKeepsBackupsWhenSomethingWasSkipped(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	path := migrated(t, h)
	if err := h.store.Delete("splunk-mcp-token"); err != nil {
		t.Fatal(err)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	h.cli.Run([]string{"restore", path})
	if left, _ := h.cli.Backups.ForFile(path); len(left) == 0 {
		t.Error("backups were removed although the restore skipped an item")
	}
}

func TestDoctorMentionsRemainingBackups(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	h.cli.Home, h.cli.Workdir = t.TempDir(), t.TempDir()
	if _, err := h.cli.Backups.Save(h.store, filepath.Join(h.cli.Home, ".zshrc"), []byte(rcFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(h.out(), "1 backup(s)") || !strings.Contains(h.out(), "keyward backups") {
		t.Errorf("doctor did not mention the backup:\n%s", h.out())
	}
}

func TestLsAndDoctorLeaveOutBackupKeys(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	h.cli.Home, h.cli.Workdir = t.TempDir(), t.TempDir()
	migrated(t, h)
	for _, args := range [][]string{{"ls"}, {"doctor"}} {
		h.stdout.Reset()
		h.cli.Run(args)
		if strings.Contains(h.out(), "keyward.backup.") {
			t.Errorf("%s lists a backup key:\n%s", args[0], h.out())
		}
	}
}

func TestBackupsRecoverWritesTheOriginalBesideItAfterYes(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	path := migrated(t, h)
	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"backups", "recover", path}); code != 0 {
		t.Fatalf("recover: %d %s", code, h.err())
	}
	found, _ := filepath.Glob(path + ".keyward-recovered-*")
	if len(found) != 1 {
		t.Fatalf("recovered files = %v", found)
	}
	if got, _ := os.ReadFile(found[0]); string(got) != rcFixture {
		t.Error("the recovered file does not match the original")
	}
	if info, err := os.Stat(found[0]); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the recovered file is not private: %v", err)
	}
	if !strings.Contains(h.out(), found[0]) || !strings.Contains(h.out(), "plaintext") {
		t.Errorf("recover did not name the file or warn about it:\n%s", h.out())
	}
	if strings.Contains(h.out()+h.err(), token) {
		t.Error("recover printed a secret")
	}
}

func TestBackupsRecoverWritesNothingWithoutYes(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	path := migrated(t, h)
	h.cli.Stdin = strings.NewReader("")
	if code := h.cli.Run([]string{"backups", "recover", path}); code == 0 {
		t.Error("recover succeeded without confirmation")
	}
	if found, _ := filepath.Glob(path + ".keyward-recovered-*"); len(found) != 0 {
		t.Errorf("wrote %v without confirmation", found)
	}
}

func TestBackupsRecoverFailsWithoutABackup(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	if code := h.cli.Run([]string{"backups", "recover", writeFixture(t, rcFixture)}); code != 1 {
		t.Errorf("exit %d, want 1: %s", code, h.err())
	}
}
