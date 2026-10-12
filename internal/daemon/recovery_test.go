package daemon_test

import (
	"path/filepath"
	"testing"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

func TestRecoveryCrossesTheSocket(t *testing.T) {
	keys := vault.NewMemory()
	store := &vault.Encrypted{Path: filepath.Join(t.TempDir(), "test.vault"), Keys: keys}
	c := start(t, &daemon.Server{Store: store})
	if err := c.Put("token", vault.NewSecret([]byte("value-1")), ""); err != nil {
		t.Fatal(err)
	}
	key, err := c.ExportKey()
	if err != nil || key.Len() != 32 {
		t.Fatalf("ExportKey = %d bytes, %v", key.Len(), err)
	}
	defer key.Destroy()
	if changed, err := c.RestoreKey(key); err != nil || changed {
		t.Errorf("RestoreKey of the current key = %v, %v; want no change", changed, err)
	}
	keys.Delete("master")
	if changed, err := c.RestoreKey(key); err != nil || !changed {
		t.Errorf("RestoreKey after loss = %v, %v", changed, err)
	}
}

func TestRecoveryNeedsAVaultStore(t *testing.T) {
	c := start(t, &daemon.Server{Store: vault.NewMemory()})
	if _, err := c.ExportKey(); err == nil {
		t.Error("ExportKey succeeded on a store without a vault key")
	}
}
