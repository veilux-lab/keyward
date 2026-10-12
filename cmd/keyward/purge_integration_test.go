//go:build darwin && cgo && integration

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// Purge removes the vault, its key, and any secret left as a separate Keychain item.
func TestPurgeVaultRemovesEverythingItStored(t *testing.T) {
	const service = "keyward-purge-test"
	keys, legacy := vault.NewKeychainService(service+"-vault-key"), vault.NewKeychainService(service)
	t.Cleanup(func() { _ = keys.Delete("master"); _ = legacy.Delete("kwtest-left-behind") })
	path := filepath.Join(t.TempDir(), "test.vault")
	v := &vault.Encrypted{Path: path, Keys: keys}
	if err := v.Put("kwtest-in-vault", vault.NewSecret([]byte("v")), ""); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Put("kwtest-left-behind", vault.NewSecret([]byte("v")), ""); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path+".recovery-shown", nil, 0o600)

	if err := purgeVault(path, service); err != nil {
		t.Fatalf("purgeVault: %v", err)
	}
	for _, file := range []string{path, path + ".recovery-shown"} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("%s remains", file)
		}
	}
	if left, _ := keys.Entries(); len(left) != 0 {
		t.Errorf("vault key remains: %v", left)
	}
	if left, _ := legacy.Entries(); len(left) != 0 {
		t.Errorf("legacy items remain: %v", left)
	}
	if err := purgeVault(path, service); err != nil {
		t.Errorf("purging an already purged vault: %v", err)
	}
}
