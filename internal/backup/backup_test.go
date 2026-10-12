package backup_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/vault"
)

const original = "export API_TOKEN='plaintext-fixture'\n"

func fixture(t *testing.T) (backup.Dir, *vault.Memory, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "project", ".zshrc")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	return backup.Default(filepath.Join(root, "home")), vault.NewMemory(), path
}

func keys(t *testing.T, store vault.Store) []string {
	t.Helper()
	entries, err := store.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if backup.IsKey(e.Name) {
			names = append(names, e.Name)
		}
	}
	return names
}

func TestSaveEncryptsSoTheFileAloneRevealsNothing(t *testing.T) {
	dir, store, path := fixture(t)
	saved, err := dir.Save(store, path, []byte(original), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(saved) != dir.Path {
		t.Errorf("backup %s is outside %s", saved, dir.Path)
	}
	entries, _ := os.ReadDir(dir.Path)
	for _, e := range entries {
		if data, _ := os.ReadFile(filepath.Join(dir.Path, e.Name())); strings.Contains(string(data), "plaintext-fixture") {
			t.Errorf("%s holds the secret in plaintext", e.Name())
		}
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
	if k := keys(t, store); len(k) != 1 {
		t.Fatalf("keys in the store = %v, want one", k)
	}
}

func TestOpenReturnsTheOriginal(t *testing.T) {
	dir, store, path := fixture(t)
	if _, err := dir.Save(store, path, []byte(original), time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if len(found) != 1 || !found[0].Encrypted() {
		t.Fatalf("ForFile = %+v", found)
	}
	got, err := backup.Open(store, found[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Bytes()) != original {
		t.Error("Open did not return the original")
	}
}

func TestOpenRejectsAModifiedBackup(t *testing.T) {
	dir, store, path := fixture(t)
	saved, _ := dir.Save(store, path, []byte(original), time.Now())
	data, _ := os.ReadFile(saved)
	data[len(data)-1] ^= 1
	if err := os.WriteFile(saved, data, 0o600); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if _, err := backup.Open(store, found[0]); err == nil {
		t.Error("opened a backup that was modified")
	}
}

func TestOpenFailsWithoutTheKey(t *testing.T) {
	dir, store, path := fixture(t)
	if _, err := dir.Save(store, path, []byte(original), time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if _, err := backup.Open(vault.NewMemory(), found[0]); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Open with another store = %v, want ErrNotFound", err)
	}
}

func TestListAndForFileFindBackupsByOriginal(t *testing.T) {
	dir, store, path := fixture(t)
	other := filepath.Join(filepath.Dir(path), ".env")
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	first, _ := dir.Save(store, path, []byte(original), now)
	second, _ := dir.Save(store, path, []byte(original), now)
	if _, err := dir.Save(store, other, []byte("A=1\n"), now.Add(time.Hour)); err != nil {
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

// Backups written before encryption hold plaintext and have no key.
func TestPlaintextBackupsFromEarlierReleasesStillListAndOpen(t *testing.T) {
	dir, store, path := fixture(t)
	if err := os.MkdirAll(dir.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir.Path, "20261004T101500Z-.zshrc")
	meta, _ := json.Marshal(map[string]any{"original": path, "created": time.Date(2026, 10, 4, 10, 15, 0, 0, time.UTC)})
	if err := os.WriteFile(old, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old+".json", meta, 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := dir.ForFile(path)
	if err != nil || len(found) != 1 || found[0].Encrypted() {
		t.Fatalf("ForFile = %+v, %v", found, err)
	}
	if got, err := backup.Open(store, found[0]); err != nil || string(got.Bytes()) != original {
		t.Errorf("Open = %v", err)
	}
}

// Earlier releases wrote backups beside the original.
func TestForFileIncludesBackupsBesideTheOriginal(t *testing.T) {
	dir, store, path := fixture(t)
	legacy := path + ".keyward-backup-20261004T101500Z"
	if err := os.WriteFile(legacy, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := dir.ForFile(path)
	if err != nil || len(found) != 1 || !found[0].Legacy || found[0].Encrypted() || found[0].Path != legacy ||
		!found[0].Created.Equal(time.Date(2026, 10, 4, 10, 15, 0, 0, time.UTC)) {
		t.Fatalf("ForFile = %+v, %v", found, err)
	}
	if err := backup.Remove(store, found[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("the old backup was not removed")
	}
}

// Deleting the key makes the backup unreadable with the current vault.
func TestRemoveDeletesTheBackupItsMetadataAndItsKey(t *testing.T) {
	dir, store, path := fixture(t)
	if _, err := dir.Save(store, path, []byte(original), time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if err := backup.Remove(store, found[0]); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir.Path); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
	if k := keys(t, store); len(k) != 0 {
		t.Errorf("keys left behind: %v", k)
	}
}

func TestRemoveStillDeletesTheFileWhenTheKeyIsAlreadyGone(t *testing.T) {
	dir, store, path := fixture(t)
	if _, err := dir.Save(store, path, []byte(original), time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if err := backup.Remove(vault.NewMemory(), found[0]); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir.Path); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}

type failingDelete struct{ vault.Store }

func (failingDelete) Delete(string) error { return errors.New("daemon unavailable") }

// Keeping the file means the removal can be retried rather than leaving a key
// that no listing points to.
func TestRemoveKeepsTheFileWhenTheKeyCannotBeDeleted(t *testing.T) {
	dir, store, path := fixture(t)
	if _, err := dir.Save(store, path, []byte(original), time.Now()); err != nil {
		t.Fatal(err)
	}
	found, _ := dir.ForFile(path)
	if err := backup.Remove(failingDelete{store}, found[0]); err == nil {
		t.Fatal("Remove reported success although the key remains")
	}
	if left, _ := dir.ForFile(path); len(left) != 1 {
		t.Errorf("backups after a failed removal: %+v", left)
	}
}

func TestSaveRefusesASymlinkedDirectory(t *testing.T) {
	dir, store, path := fixture(t)
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(dir.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.Save(store, path, []byte(original), time.Now()); err == nil {
		t.Fatal("saved through a symlinked backup directory")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("wrote into the symlink target: %v", entries)
	}
	if k := keys(t, store); len(k) != 0 {
		t.Errorf("a key was stored for a backup that was never written: %v", k)
	}
}

func TestSaveLeavesNoKeyWhenTheFileCannotBeWritten(t *testing.T) {
	dir, store, path := fixture(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	// A directory where the metadata belongs makes the second write fail.
	if err := os.MkdirAll(filepath.Join(dir.Path, "20261005T120000Z-.zshrc.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.Save(store, path, []byte(original), now); err == nil {
		t.Fatal("Save succeeded although its metadata could not be written")
	}
	if k := keys(t, store); len(k) != 0 {
		t.Errorf("keys left behind: %v", k)
	}
	if _, err := os.Stat(filepath.Join(dir.Path, "20261005T120000Z-.zshrc")); !os.IsNotExist(err) {
		t.Error("the backup was left without its metadata")
	}
}

func TestEmptyDirectoryListsNothing(t *testing.T) {
	dir, _, _ := fixture(t)
	if found, err := dir.List(); err != nil || len(found) != 0 {
		t.Fatalf("List = %v, %v", found, err)
	}
}

func TestIsKeyMatchesOnlyBackupKeys(t *testing.T) {
	for name, want := range map[string]bool{
		"keyward.backup.0123456789abcdef": true,
		"github-token":                    false,
		"keyward-backup":                  false,
	} {
		if got := backup.IsKey(name); got != want {
			t.Errorf("IsKey(%q) = %v, want %v", name, got, want)
		}
	}
}
