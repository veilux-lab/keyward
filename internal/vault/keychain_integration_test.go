//go:build darwin && cgo && integration

// This is the only test that touches the real Keychain, which is why it sits
// behind a build tag and out of `make test`. Run it with `make test-integration`.
//
// It uses a dedicated service name, so it cannot see or modify a real keyward
// entry no matter what the contract suite does.

package vault_test

import (
	"errors"
	"testing"

	"github.com/nwokolo24/keyward/internal/vault"
	"github.com/nwokolo24/keyward/internal/vault/vaulttest"
)

// testService isolates these items from the real "keyward" service.
const testService = "keyward-integration-test"

// The real store is held to exactly the contract the in-memory fake passes. That
// equivalence is the point: it is what lets every layer above be tested against
// the fake and still be trusted against the Keychain.
func TestKeychainContract(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store {
		return vault.NewKeychainService(testService)
	})
}

// Values must survive leaving the process. The fake cannot demonstrate this, and
// it is the one property that actually matters about the Keychain.
func TestKeychainPersistsAcrossStores(t *testing.T) {
	const name = "kwtest-persist"
	value := []byte("eyJraWQiOiJzcGx1bmsi")

	writer := vault.NewKeychainService(testService)
	_ = writer.Delete(name)
	t.Cleanup(func() { _ = writer.Delete(name) })

	if err := writer.Put(name, vault.NewSecret(value), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A separate store value, as a later process would construct.
	reader := vault.NewKeychainService(testService)
	got, err := reader.Get(name)
	if err != nil {
		t.Fatalf("Get from a second store: %v", err)
	}
	if string(got.Bytes()) != string(value) {
		t.Error("value did not survive being read through a different store")
	}
}

// Items written under one service must be invisible to another, which is what
// keeps the test service from colliding with real entries.
func TestKeychainServicesAreIsolated(t *testing.T) {
	const name = "kwtest-isolation"

	a := vault.NewKeychainService(testService)
	b := vault.NewKeychainService(testService + "-other")

	_ = a.Delete(name)
	_ = b.Delete(name)
	t.Cleanup(func() { _ = a.Delete(name); _ = b.Delete(name) })

	if err := a.Put(name, vault.NewSecret([]byte("v")), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := b.Get(name); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get from a different service = %v, want ErrNotFound", err)
	}
	if err := b.Put(name, vault.NewSecret([]byte("v")), ""); err != nil {
		t.Errorf("Put under a different service = %v, want success", err)
	}
}

// Entries must not report entries belonging to other services.
func TestKeychainEntriesAreScopedToService(t *testing.T) {
	const name = "kwtest-scope"

	a := vault.NewKeychainService(testService)
	b := vault.NewKeychainService(testService + "-other")
	_ = b.Delete(name)
	t.Cleanup(func() { _ = b.Delete(name) })

	if err := b.Put(name, vault.NewSecret([]byte("v")), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := a.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	for _, e := range entries {
		if e.Name == name {
			t.Errorf("Entries returned %q, which belongs to another service", e.Name)
		}
	}
}

// An empty service is a programming error, not something to paper over: it would
// silently share a namespace with every other unscoped item.
func TestKeychainRejectsEmptyService(t *testing.T) {
	s := vault.NewKeychainService("")
	if _, err := s.Get("kwtest-anything"); err == nil {
		t.Error("Get with an empty service succeeded, want an error")
	}
}
