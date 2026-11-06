package vault_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// On a new Mac a command can run before the old vault is copied over. Reading
// must not create a key: a new key would later seal values the real one cannot open.
func TestAReadBeforeTheVaultArrivesCreatesNoKey(t *testing.T) {
	s, keys, _ := encrypted(t)
	if _, err := s.Get("github-token"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
	if entries, _ := keys.Entries(); len(entries) != 0 {
		t.Errorf("a read created a key: %v", entries)
	}
}

// A vault that arrives after the daemon cached another key is refused, with the
// way out, instead of being mixed with values sealed under the wrong key.
func TestACachedKeyIsCheckedAgainstAVaultThatArrivesLater(t *testing.T) {
	old, _, _ := encrypted(t)
	put(t, old, "github-token", "value-from-the-old-mac")
	fresh, _, _ := encrypted(t)
	put(t, fresh, "made-on-the-new-mac", "x") // creates and caches a new key
	data, _ := os.ReadFile(old.Path)
	os.WriteFile(fresh.Path, data, 0o600) // the old vault is copied over

	_, err := fresh.Get("github-token")
	if err == nil || !strings.Contains(err.Error(), "keyward recovery restore") {
		t.Fatalf("Get = %v, want a mismatch that names recovery restore", err)
	}
	if err := fresh.Put("another", vault.NewSecret([]byte("y")), ""); err == nil {
		t.Error("a value was sealed into a vault its key cannot open")
	}
	if now, _ := os.ReadFile(fresh.Path); string(now) != string(data) {
		t.Error("the copied vault was changed")
	}
}

// Restoring a key never destroys the one it replaces, in case values were sealed
// under it.
func TestRestoreKeyKeepsTheKeyItReplaces(t *testing.T) {
	old, _, _ := encrypted(t)
	put(t, old, "github-token", "v")
	code, err := old.ExportKey()
	if err != nil {
		t.Fatal(err)
	}
	fresh, keys, _ := encrypted(t)
	put(t, fresh, "made-on-the-new-mac", "x")
	orphan, _ := keys.Get("master")
	data, _ := os.ReadFile(old.Path)
	os.WriteFile(fresh.Path, data, 0o600)

	if changed, err := fresh.RestoreKey(code); err != nil || !changed {
		t.Fatalf("RestoreKey = %v, %v", changed, err)
	}
	entries, _ := keys.Entries()
	var kept bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name, "master.replaced-") {
			v, _ := keys.Get(e.Name)
			kept = v.Equal(orphan)
		}
	}
	if !kept {
		t.Errorf("the replaced key was not kept: %v", entries)
	}
	if got, err := fresh.Get("github-token"); err != nil || string(got.Bytes()) != "v" {
		t.Errorf("after restore, Get = %v", err)
	}
}
