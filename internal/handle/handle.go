// Package handle parses and formats keyward secret references.
//
// A reference stands in for a secret wherever a value would normally sit: in a
// shell rc file, an MCP server config, a .env file. Config holds the reference,
// keyward resolves it at execution time, and the value itself never lands on
// disk or in an agent's context.
package handle

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// Prefix marks a string as a reference rather than a value. It is matched
	// case-sensitively so that detection stays unambiguous and allocation-free.
	Prefix = "cap://"

	// MaxNameLen bounds a reference name.
	MaxNameLen = 128
)

var (
	// ErrNotHandle means the string does not claim to be a reference at all and
	// should be treated as a literal value.
	ErrNotHandle = errors.New("not a keyward reference")

	// ErrEmptyName means the prefix was present with no name after it.
	ErrEmptyName = errors.New("reference has no name")

	// ErrInvalidName means the name contains characters a reference may not use.
	ErrInvalidName = errors.New("invalid reference name")

	// ErrNameTooLong means the name exceeds MaxNameLen.
	ErrNameTooLong = errors.New("reference name too long")
)

// Handle is a parsed, canonical reference to a stored secret.
type Handle struct {
	// Name identifies the secret in the vault. Always lowercase.
	Name string
}

// IsRef reports whether s claims to be a reference.
//
// This is deliberately weaker than Parse: a malformed reference such as
// "cap://bad name" still returns true. Callers scanning an environment need to
// tell "this is a broken reference, fail loudly" apart from "this is a literal
// value, pass it through" — collapsing the two would hand a typo to a program
// as though it were a secret.
func IsRef(s string) bool {
	return strings.HasPrefix(s, Prefix)
}

// Parse validates s and returns its canonical Handle. Names are lowercased, so
// parsing is idempotent over String.
//
// Errors never quote the input. Parse is routinely called on strings that turn
// out to be real secrets, and an error message is a short trip to a log file.
func Parse(s string) (Handle, error) {
	if !IsRef(s) {
		return Handle{}, ErrNotHandle
	}

	name := strings.ToLower(s[len(Prefix):])
	switch {
	case name == "":
		return Handle{}, ErrEmptyName
	case len(name) > MaxNameLen:
		return Handle{}, fmt.Errorf("%d characters, limit is %d: %w", len(name), MaxNameLen, ErrNameTooLong)
	}
	if err := validateName(name); err != nil {
		return Handle{}, err
	}
	return Handle{Name: name}, nil
}

// String returns the canonical reference form. It contains only the name, never
// a resolved value, so it is safe to log.
func (h Handle) String() string {
	return Prefix + h.Name
}

// validateName allows lowercase ASCII letters, digits, and the separators
// "-", "_", and ".". Names must start and end alphanumeric, which keeps them
// unambiguous in shell, JSON, and env-file contexts.
func validateName(name string) error {
	for i := 0; i < len(name); i++ {
		if !isNameByte(name[i]) {
			return fmt.Errorf("%q: %w", name, ErrInvalidName)
		}
	}
	if !isAlnum(name[0]) || !isAlnum(name[len(name)-1]) {
		return fmt.Errorf("%q must start and end with a letter or digit: %w", name, ErrInvalidName)
	}
	return nil
}

func isNameByte(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_' || c == '.'
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
