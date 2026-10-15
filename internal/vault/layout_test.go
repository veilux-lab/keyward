package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// The vault lives inside keyward's own folder, so a purge removes one folder.
func TestTheVaultLivesInKeywardsFolder(t *testing.T) {
	want := filepath.Join("/h", "Library", "Application Support", "keyward", "vault", "keyward.vault")
	if got := vault.DefaultPath("/h", "keyward"); got != want {
		t.Errorf("DefaultPath = %s, want %s", got, want)
	}
}

// A vault from before the move is moved in once, with its recovery marker, and
// its old folder is removed when nothing else is in it.
func TestMoveLegacyBringsAnOldVaultIn(t *testing.T) {
	home := t.TempDir()
	old := filepath.Join(home, "Library", "Application Support", "keyward-vault")
	os.MkdirAll(old, 0o700)
	os.WriteFile(filepath.Join(old, "keyward.vault"), []byte("sealed"), 0o600)
	os.WriteFile(filepath.Join(old, "keyward.vault.recovery-shown"), nil, 0o600)
	if err := vault.MoveLegacy(home, "keyward"); err != nil {
		t.Fatal(err)
	}
	moved := vault.DefaultPath(home, "keyward")
	if data, err := os.ReadFile(moved); err != nil || string(data) != "sealed" {
		t.Errorf("moved vault = %q, %v", data, err)
	}
	if _, err := os.Stat(moved + ".recovery-shown"); err != nil {
		t.Errorf("recovery marker not moved: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old folder still there: %v", err)
	}
	if err := vault.MoveLegacy(home, "keyward"); err != nil {
		t.Errorf("a second move: %v", err)
	}
}

// A vault already in the new place wins; the old one is never moved over it.
func TestMoveLegacyNeverReplacesTheCurrentVault(t *testing.T) {
	home := t.TempDir()
	old := filepath.Join(home, "Library", "Application Support", "keyward-vault")
	os.MkdirAll(old, 0o700)
	os.WriteFile(filepath.Join(old, "keyward.vault"), []byte("old"), 0o600)
	current := vault.DefaultPath(home, "keyward")
	os.MkdirAll(filepath.Dir(current), 0o700)
	os.WriteFile(current, []byte("current"), 0o600)
	if err := vault.MoveLegacy(home, "keyward"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(current); string(data) != "current" {
		t.Errorf("current vault = %q", data)
	}
	if _, err := os.Stat(filepath.Join(old, "keyward.vault")); err != nil {
		t.Errorf("the old vault was deleted: %v", err)
	}
}
