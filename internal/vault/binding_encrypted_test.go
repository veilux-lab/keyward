package vault_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

func gh() vault.Binding {
	return vault.Binding{Kind: vault.BindingProgram, Program: "/opt/homebrew/bin/gh"}
}

// vaultVersion reads the version field from the vault file on disk.
func vaultVersion(t *testing.T, path string) int {
	t.Helper()
	var file struct {
		Version int `json:"version"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Version
}

// The file stays version 1 until the first binding, so an older keyward can
// still read it until then, and drops back once the last binding is removed.
func TestEncryptedVersionTracksBindings(t *testing.T) {
	s, _, _ := encrypted(t)
	put(t, s, "token", "v")
	if v := vaultVersion(t, s.Path); v != 1 {
		t.Errorf("version with no binding = %d, want 1", v)
	}
	if err := s.Bind("token", gh()); err != nil {
		t.Fatal(err)
	}
	if v := vaultVersion(t, s.Path); v != 2 {
		t.Errorf("version with a binding = %d, want 2", v)
	}
	if err := s.Unbind("token", gh()); err != nil {
		t.Fatal(err)
	}
	if v := vaultVersion(t, s.Path); v != 1 {
		t.Errorf("version after removing the last binding = %d, want 1", v)
	}
}

// Removing or changing a binding by hand must not silently unbind the secret:
// the binding is part of the seal, so the value no longer decrypts.
func TestEncryptedBindingIsPartOfTheSeal(t *testing.T) {
	s, _, _ := encrypted(t)
	put(t, s, "token", "v")
	if err := s.Bind("token", gh()); err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	data, _ := os.ReadFile(s.Path)
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var entries map[string]map[string]any
	json.Unmarshal(file["entries"], &entries)
	delete(entries["token"], "bindings")
	file["entries"], _ = json.Marshal(entries)
	data, _ = json.Marshal(file)
	os.WriteFile(s.Path, data, 0o600)

	if _, err := s.Get("token"); err == nil {
		t.Error("a value whose binding was removed by hand still decrypted")
	}
}

// Binding a secret that does not exist, before any vault exists, must not create
// a vault key as a side effect — the same guard Get keeps.
func TestEncryptedBindMissingDoesNotCreateAKey(t *testing.T) {
	s, keys, _ := encrypted(t)
	if err := s.Bind("missing", gh()); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Bind missing = %v, want ErrNotFound", err)
	}
	if entries, _ := keys.Entries(); len(entries) != 0 {
		t.Errorf("Bind of a missing secret created a vault key: %v", entries)
	}
	if _, err := os.Stat(s.Path); err == nil {
		t.Error("Bind of a missing secret created a vault file")
	}
}

// A vault from a newer keyward, whose version this one does not know, is refused
// whole rather than read with its bindings dropped.
func TestEncryptedRefusesANewerVersion(t *testing.T) {
	s, _, _ := encrypted(t)
	put(t, s, "token", "v")
	var file map[string]json.RawMessage
	data, _ := os.ReadFile(s.Path)
	json.Unmarshal(data, &file)
	file["version"] = json.RawMessage("99")
	data, _ = json.Marshal(file)
	os.WriteFile(s.Path, data, 0o600)

	if _, err := s.Entries(); err == nil {
		t.Error("read a vault whose version this keyward does not know")
	}
}
