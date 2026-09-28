package vault_test

import (
	"testing"

	"github.com/nwokolo24/keyward/internal/vault"
	"github.com/nwokolo24/keyward/internal/vault/vaulttest"
)

// The fake is held to the same contract as the real Keychain store. Every piece
// of logic above vault.Store is tested against this, which is what keeps the
// cgo layer thin enough to be trustworthy.
func TestMemory(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store {
		return vault.NewMemory()
	})
}

// A Memory store must not share state with another, or tests using it would
// interfere with each other.
func TestMemoryInstancesAreIndependent(t *testing.T) {
	a, b := vault.NewMemory(), vault.NewMemory()

	if err := a.Put("token", vault.NewSecret([]byte("v")), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := b.Get("token"); err == nil {
		t.Error("a second Memory store saw the first store's secret")
	}
}

// Seed is a convenience for tests of higher layers; it must reject the same
// names and values Put does rather than quietly creating bad state.
func TestMemorySeedValidates(t *testing.T) {
	m := vault.NewMemory()

	if err := m.Seed(map[string]string{"splunk-mcp-token": "abc123"}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	got, err := m.Get("splunk-mcp-token")
	if err != nil {
		t.Fatalf("Get after Seed: %v", err)
	}
	if string(got.Bytes()) != "abc123" {
		t.Errorf("Get after Seed = %q, want %q", got.Bytes(), "abc123")
	}

	if err := m.Seed(map[string]string{"bad name": "v"}); err == nil {
		t.Error("Seed accepted an invalid name")
	}
	if err := m.Seed(map[string]string{"empty-value": ""}); err == nil {
		t.Error("Seed accepted an empty value")
	}
}
