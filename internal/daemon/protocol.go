// Package daemon serves a vault.Store over a Unix socket, so that one long-lived
// process is the only thing that touches the Keychain.
//
// Keychain items trust the binary that created them, so every rebuild of keyward
// meant an approval prompt that a non-interactive command cannot answer. With the
// daemon, only its binary needs approving and the CLI can change freely. See
// obstacle 2a in doc/obstacles.md.
package daemon

import (
	"errors"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/vault"
)

// maxMessage bounds a request or response. Far above any real credential.
const maxMessage = 1 << 20

// One JSON request per connection, answered by one JSON response.
type request struct {
	Op    string `json:"op"`
	Name  string `json:"name,omitempty"`
	Value []byte `json:"value,omitempty"`
	Note  string `json:"note,omitempty"`
}

type response struct {
	// Version answers ping, so a client can tell an outdated daemon apart.
	Version string        `json:"version,omitempty"`
	Value   []byte        `json:"value,omitempty"`
	Entries []vault.Entry `json:"entries,omitempty"`

	// Code is empty on success. Message carries the error text, which by the
	// Store contract never contains a value.
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// errorCodes carries sentinel errors across the socket, so callers on the client
// side can still branch on them with errors.Is.
var errorCodes = []struct {
	code string
	err  error
}{
	{"not_found", vault.ErrNotFound},
	{"exists", vault.ErrExists},
	{"empty_value", vault.ErrEmptyValue},
	{"denied", vault.ErrDenied},
	{"not_handle", handle.ErrNotHandle},
	{"empty_name", handle.ErrEmptyName},
	{"invalid_name", handle.ErrInvalidName},
	{"name_too_long", handle.ErrNameTooLong},
}

// codeOther marks an error with no sentinel; only its message crosses.
const codeOther = "other"

func errorResponse(err error) response {
	for _, c := range errorCodes {
		if errors.Is(err, c.err) {
			return response{Code: c.code, Message: err.Error()}
		}
	}
	return response{Code: codeOther, Message: err.Error()}
}

func (r response) err() error {
	if r.Code == "" {
		return nil
	}
	for _, c := range errorCodes {
		if r.Code == c.code {
			return &remoteError{msg: r.Message, sentinel: c.err}
		}
	}
	return errors.New(r.Message)
}

// remoteError keeps the server's message while matching the sentinel it carried.
type remoteError struct {
	msg      string
	sentinel error
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.sentinel }
