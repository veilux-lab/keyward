// Package vault stores and retrieves secret values.
//
// Store is the seam that keeps the rest of keyward testable. The real
// implementation talks to the macOS Keychain through cgo, which cannot be
// meaningfully unit tested: it touches live OS state, may prompt, and would
// pollute the developer's own Keychain. So every piece of logic above this
// interface is tested against Memory, the cgo layer is kept thin enough to be
// nearly declarative, and both are held to the same contract by the vaulttest
// package.
package vault

import "errors"

var (
	// ErrNotFound means no secret is stored under that name.
	ErrNotFound = errors.New("secret not found")

	// ErrExists means Put was called for a name that already has a value.
	ErrExists = errors.New("secret already exists")

	// ErrEmptyValue means the value was empty. Storing one is nearly always an
	// upstream bug, and it produces a uniquely unhelpful failure downstream: a
	// variable that is present but blank, and a connect timeout with no
	// visible cause.
	ErrEmptyValue = errors.New("secret value is empty")

	// ErrDenied means the secret exists but access was refused — by the user
	// declining a prompt, by the keychain being locked, or by a missing
	// entitlement.
	//
	// Distinct from ErrNotFound on purpose. "You said no" and "it is not there"
	// call for different messages, and the difference becomes load-bearing if
	// resolution is ever gated behind a biometric prompt.
	ErrDenied = errors.New("access to the secret was denied")
)

// Entry is a stored secret's metadata. Deliberately not its value: this is what
// listing and reporting work from, so no code path that enumerates the vault can
// accidentally hold a credential.
type Entry struct {
	// Name is the canonical reference name.
	Name string

	// Note records where the value came from, such as "/Users/x/.zshrc:9". Empty
	// means nothing recorded it — which is itself information: a secret added by
	// hand was created deliberately, and should never be mistaken for a leftover.
	//
	// Keychain attributes are readable more freely than values, so a note holds
	// only a path or a short description. Never anything sensitive.
	Note string
}

// Store holds secret values keyed by name.
//
// Names are normalised by handle.Normalize, so a Store is keyed by exactly the
// names a cap:// reference can carry. Implementations must reject a name that
// does not normalise.
//
// Errors may quote a name. They must never quote a value.
type Store interface {
	// Get returns the secret stored under name, or ErrNotFound.
	//
	// The returned Secret is independent of the Store's own storage: a caller may
	// Destroy it without affecting what is stored.
	Get(name string) (Secret, error)

	// Put stores a new secret, returning ErrExists if name is already taken.
	//
	// Put never overwrites. Silently replacing a credential is how a working
	// setup breaks with no trace of what changed, so overwriting is Replace's
	// job and a caller has to say which it means.
	//
	// note records provenance and may be empty. See Entry.Note.
	Put(name string, value Secret, note string) error

	// Replace overwrites an existing secret, returning ErrNotFound if absent.
	//
	// note replaces any previous provenance, since a new value came from somewhere
	// new.
	Replace(name string, value Secret, note string) error

	// Delete removes a secret, returning ErrNotFound if absent.
	Delete(name string) error

	// Entries returns metadata for every stored secret, sorted by name. Never
	// values.
	Entries() ([]Entry, error)
}
