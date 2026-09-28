package vault

import (
	"crypto/subtle"
	"encoding/json"
)

// Redacted is what a Secret renders as, in every format and every verb.
const Redacted = "vault.Secret(redacted)"

// Secret holds a credential value.
//
// It exists instead of a bare []byte for one reason: a []byte prints itself. A
// stray %v in a log line, an error wrapping a struct, or a marshalled audit
// record would each be enough to write a live credential somewhere permanent.
// Secret renders as Redacted through String, GoString, and MarshalJSON, so the
// value can only escape by calling Bytes explicitly.
//
// A zero Secret is valid and empty.
type Secret struct {
	b []byte
}

// NewSecret copies value into a new Secret. The copy matters: callers reuse and
// zero their own buffers, and a stored secret must not change underneath them.
// An empty value yields a zero Secret, which every Store rejects.
func NewSecret(value []byte) Secret {
	if len(value) == 0 {
		return Secret{}
	}
	b := make([]byte, len(value))
	copy(b, value)
	return Secret{b: b}
}

// Bytes returns the value. This is the only way it leaves the type, which is
// what makes the leak surface small enough to audit.
//
// The returned slice aliases the Secret's storage. Do not modify it, and note
// that it reads as zeroes once Destroy has been called.
func (s Secret) Bytes() []byte { return s.b }

// Len returns the length of the value in bytes. Safe to log.
func (s Secret) Len() int { return len(s.b) }

// IsZero reports whether the Secret holds no value.
func (s Secret) IsZero() bool { return len(s.b) == 0 }

// String implements fmt.Stringer, covering %v, %s, and %q.
func (s Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer, covering %#v.
func (s Secret) GoString() string { return Redacted }

// MarshalJSON keeps secrets out of audit records and serialised errors.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// Equal reports whether two Secrets hold the same value, in constant time with
// respect to content so a comparison cannot be turned into an oracle.
func (s Secret) Equal(other Secret) bool {
	if len(s.b) == 0 || len(other.b) == 0 {
		return len(s.b) == len(other.b)
	}
	return subtle.ConstantTimeCompare(s.b, other.b) == 1
}

// Destroy zeroes the value and empties the Secret.
//
// This is a reduction in exposure, not a guarantee. Go's garbage collector may
// have copied the value while moving it, and those copies are unreachable and
// cannot be cleared. Do not describe a destroyed secret as unrecoverable from
// process memory.
func (s *Secret) Destroy() {
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}
