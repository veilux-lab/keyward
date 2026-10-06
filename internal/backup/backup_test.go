package backup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/backup"
)

const original = "export API_TOKEN='plaintext-fixture'\n"

func fixture(t *testing.T) (backup.Dir, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "project", ".zshrc")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	return backup.Default(filepath.Join(root, "home")), path
}

func TestSaveKeepsThePlaintextPrivateAndAwayFromTheOriginal(t *testing.T) {
	dir, path := fixture(t)
	saved, err := dir.Save(path, []byte(original), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(saved) != dir.Path {
		t.Errorf("backup %s is outside %s", saved, dir.Path)
	}
	if got, _ := os.ReadFile(saved); string(got) != original {
		t.Error("the backup does not match the original")
	}
	for path, mode := range map[string]os.FileMode{saved: 0o600, dir.Path: 0o700} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s: mode %v, want %v (%v)", path, info.Mode().Perm(), mode, err)
		}
	}
	siblings, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*"))
	if len(siblings) != 1 {
		t.Errorf("files written beside the original: %v", siblings)
	}
	entries, _ := os.ReadDir(dir.Path)
	for _, e := range entries {
		full := filepath.Join(dir.Path, e.Name())
		if data, _ := os.ReadFile(full); full != saved && strings.Contains(string(data), "plaintext-fixture") {
			t.Errorf("metadata %s copies the secret", e.Name())
		}
	}
}

func TestListAndForFileFindBackupsByOriginal(t *testing.T) {
	dir, path := fixture(t)
	other := filepath.Join(filepath.Dir(path), ".env")
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	first, _ := dir.Save(path, []byte(original), now)
	second, _ := dir.Save(path, []byte(original), now)
	if _, err := dir.Save(other, []byte("A=1\n"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("a second backup in the same instant overwrote the first")
	}
	all, err := dir.List()
	if err != nil || len(all) != 3 || all[2].Original != other || !all[0].Created.Equal(now) {
		t.Fatalf("List = %+v, %v", all, err)
	}
	mine, err := dir.ForFile(path)
	if err != nil || len(mine) != 2 {
		t.Fatalf("ForFile = %+v, %v", mine, err)
	}
}

// Earlier releases wrote backups beside the original.
func TestForFileIncludesBackupsBesideTheOriginal(t *testing.T) {
	dir, path := fixture(t)
	legacy := path + ".keyward-backup-20261004T101500Z"
	if err := os.WriteFile(legacy, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := dir.ForFile(path)
	if err != nil || len(found) != 1 || !found[0].Legacy || found[0].Path != legacy ||
		!found[0].Created.Equal(time.Date(2026, 10, 4, 10, 15, 0, 0, time.UTC)) {
		t.Fatalf("ForFile = %+v, %v", found, err)
	}
	if err := backup.Remove(found[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("the old backup was not removed")
	}
}

func TestRemoveDeletesTheBackupAndItsMetadata(t *testing.T) {
	dir, path := fixture(t)
	if _, err := dir.Save(path, []byte(original), time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if err := backup.Remove(found[0]); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir.Path); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestSaveRefusesASymlinkedDirectory(t *testing.T) {
	dir, path := fixture(t)
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(dir.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.Save(path, []byte(original), time.Now()); err == nil {
		t.Fatal("saved plaintext through a symlinked backup directory")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("wrote into the symlink target: %v", entries)
	}
}

func TestEmptyDirectoryListsNothing(t *testing.T) {
	dir, _ := fixture(t)
	if found, err := dir.List(); err != nil || len(found) != 0 {
		t.Fatalf("List = %v, %v", found, err)
	}
}
