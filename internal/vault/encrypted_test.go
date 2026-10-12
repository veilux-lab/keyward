package vault_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
	"github.com/veilux-lab/keyward/internal/vault/vaulttest"
)

func encrypted(t *testing.T) (*vault.Encrypted, *vault.Memory, *vault.Memory) {
	t.Helper()
	keys, legacy := vault.NewMemory(), vault.NewMemory()
	return &vault.Encrypted{Path: filepath.Join(t.TempDir(), "vault", "keyward.vault"), Keys: keys, Legacy: legacy}, keys, legacy
}

func TestEncrypted(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store {
		s, _, _ := encrypted(t)
		return s
	})
}

func put(t *testing.T, s vault.Store, name, value string) {
	t.Helper()
	if err := s.Put(name, vault.NewSecret([]byte(value)), ""); err != nil {
		t.Fatalf("Put %s: %v", name, err)
	}
}

func TestEncryptedFileHoldsNoValuesAndIsPrivate(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "github-token", "ghp_plaintextFixture0123")
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ghp_plaintextFixture0123") {
		t.Error("the vault file holds a value in plaintext")
	}
	for path, mode := range map[string]os.FileMode{s.Path: 0o600, filepath.Dir(s.Path): 0o700} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s: mode %v, want %v (%v)", path, info.Mode().Perm(), mode, err)
		}
	}
	if entries, _ := keys.Entries(); len(entries) != 1 {
		t.Errorf("key store holds %v, want only the master key", entries)
	}
}

// The value is only as safe as the key: a second store with the same file and
// key reads it, which is what a daemon restart is.
func TestEncryptedSurvivesARestart(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "token", "value-1")
	again := &vault.Encrypted{Path: s.Path, Keys: keys}
	got, err := again.Get("token")
	if err != nil || string(got.Bytes()) != "value-1" {
		t.Fatalf("Get after restart = %v", err)
	}
}

func TestEncryptedRefusesTheWrongKey(t *testing.T) {
	s, _, _ := encrypted(t)
	put(t, s, "token", "value-1")
	other := &vault.Encrypted{Path: s.Path, Keys: vault.NewMemory()}
	// A missing key must not be replaced by a new one: that would orphan every value.
	if _, err := other.Get("token"); err == nil || !strings.Contains(err.Error(), "key") {
		t.Errorf("Get with no key = %v, want a key error", err)
	}
	wrong := vault.NewMemory()
	if err := wrong.Put("master", vault.NewSecret([]byte(strings.Repeat("ab", 32))), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := (&vault.Encrypted{Path: s.Path, Keys: wrong}).Get("token"); err == nil {
		t.Error("read the vault with the wrong key")
	}
}

// Swapping two entries' ciphertexts must not move a value to another name.
func TestEncryptedBindsEachValueToItsName(t *testing.T) {
	s, _, _ := encrypted(t)
	put(t, s, "a", "value-a")
	put(t, s, "b", "value-b")
	var file map[string]json.RawMessage
	data, _ := os.ReadFile(s.Path)
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var entries map[string]map[string]any
	json.Unmarshal(file["entries"], &entries)
	entries["a"]["value"], entries["b"]["value"] = entries["b"]["value"], entries["a"]["value"]
	file["entries"], _ = json.Marshal(entries)
	data, _ = json.Marshal(file)
	os.WriteFile(s.Path, data, 0o600)
	if _, err := s.Get("a"); err == nil {
		t.Error("a value swapped in from another entry decrypted")
	}
}

type deniedKeys struct{ vault.Store }

func (deniedKeys) Get(string) (vault.Secret, error) { return vault.Secret{}, vault.ErrDenied }

// A denied key fails the request; the next one asks again.
func TestEncryptedReportsADeniedKey(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "token", "value-1")
	denied := &vault.Encrypted{Path: s.Path, Keys: deniedKeys{keys}}
	if _, err := denied.Get("token"); !errors.Is(err, vault.ErrDenied) {
		t.Errorf("Get = %v, want ErrDenied", err)
	}
}

type countingKeys struct {
	vault.Store
	gets atomic.Int32
}

func (c *countingKeys) Get(name string) (vault.Secret, error) {
	c.gets.Add(1)
	return c.Store.Get(name)
}

// One Keychain read per daemon, so an upgrade asks once.
func TestEncryptedReadsTheKeyOnce(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "token", "value-1")
	counting := &countingKeys{Store: keys}
	again := &vault.Encrypted{Path: s.Path, Keys: counting}
	for range 3 {
		if _, err := again.Get("token"); err != nil {
			t.Fatal(err)
		}
	}
	if n := counting.gets.Load(); n != 1 {
		t.Errorf("key read %d times, want 1", n)
	}
}

// Items stored before the vault existed move in on first use and leave the
// Keychain, so a later rm cannot leave a stale copy behind.
func TestEncryptedMovesLegacyItemsIn(t *testing.T) {
	s, _, legacy := encrypted(t)
	put(t, legacy, "old-token", "old-value")
	if err := legacy.Replace("old-token", vault.NewSecret([]byte("old-value")), "/Users/x/.zshrc:3"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("old-token")
	if err != nil || string(got.Bytes()) != "old-value" {
		t.Fatalf("Get = %v", err)
	}
	if left, _ := legacy.Entries(); len(left) != 0 {
		t.Errorf("legacy items remain: %v", left)
	}
	entries, _ := s.Entries()
	if len(entries) != 1 || entries[0].Note != "/Users/x/.zshrc:3" {
		t.Errorf("Entries = %+v, want the item with its provenance", entries)
	}
}

type denyOne struct {
	*vault.Memory
	name string
}

func (d denyOne) Get(name string) (vault.Secret, error) {
	if name == d.name {
		return vault.Secret{}, vault.ErrDenied
	}
	return d.Memory.Get(name)
}

// A legacy item the user denies stays where it is, still listed, and is moved on
// a later request instead of disappearing.
func TestEncryptedKeepsADeniedLegacyItemVisible(t *testing.T) {
	keys, mem := vault.NewMemory(), vault.NewMemory()
	put(t, mem, "allowed", "v1")
	put(t, mem, "denied", "v2")
	path := filepath.Join(t.TempDir(), "keyward.vault")
	s := &vault.Encrypted{Path: path, Keys: keys, Legacy: denyOne{mem, "denied"}}
	if _, err := s.Get("allowed"); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.Entries()
	if len(entries) != 2 {
		t.Fatalf("Entries = %+v, want both", entries)
	}
	if _, err := s.Get("denied"); !errors.Is(err, vault.ErrDenied) {
		t.Errorf("Get denied = %v, want ErrDenied", err)
	}
	if err := s.Put("denied", vault.NewSecret([]byte("x")), ""); !errors.Is(err, vault.ErrExists) {
		t.Errorf("Put over a legacy item = %v, want ErrExists", err)
	}

	later := &vault.Encrypted{Path: path, Keys: keys, Legacy: mem}
	if got, err := later.Get("denied"); err != nil || string(got.Bytes()) != "v2" {
		t.Errorf("Get once allowed = %v", err)
	}
}

// Deleting needs no authorisation, so removing a legacy item never asks.
func TestEncryptedDeletesALegacyItemWithoutReadingIt(t *testing.T) {
	keys, mem := vault.NewMemory(), vault.NewMemory()
	put(t, mem, "denied", "v2")
	s := &vault.Encrypted{Path: filepath.Join(t.TempDir(), "keyward.vault"), Keys: keys, Legacy: denyOne{mem, "denied"}}
	if err := s.Delete("denied"); err != nil {
		t.Fatalf("Delete = %v", err)
	}
	if left, _ := mem.Entries(); len(left) != 0 {
		t.Errorf("legacy items remain: %v", left)
	}
}

func TestEncryptedReplaceMovesALegacyItemIn(t *testing.T) {
	keys, mem := vault.NewMemory(), vault.NewMemory()
	put(t, mem, "denied", "old")
	s := &vault.Encrypted{Path: filepath.Join(t.TempDir(), "keyward.vault"), Keys: keys, Legacy: denyOne{mem, "denied"}}
	if err := s.Replace("denied", vault.NewSecret([]byte("new")), ""); err != nil {
		t.Fatalf("Replace = %v", err)
	}
	if got, err := s.Get("denied"); err != nil || string(got.Bytes()) != "new" {
		t.Errorf("Get = %v", err)
	}
	if left, _ := mem.Entries(); len(left) != 0 {
		t.Errorf("legacy items remain: %v", left)
	}
}

func TestEncryptedRefusesASymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	dir := filepath.Join(root, "vault")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	s := &vault.Encrypted{Path: filepath.Join(dir, "keyward.vault"), Keys: vault.NewMemory()}
	if err := s.Put("token", vault.NewSecret([]byte("v")), ""); err == nil {
		t.Error("wrote through a symlinked vault directory")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("wrote into the symlink target: %v", entries)
	}
}
