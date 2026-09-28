package cli

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// TrimSecret removes a single trailing newline, and a preceding carriage return
// if present.
//
// `echo` appends one, and piping is the normal way to supply a value, so without
// this nearly every stored secret would carry an invisible trailing byte and fail
// authentication for a reason nobody would guess. Exactly one newline is removed,
// so a multi-line secret such as a PEM key keeps its internal structure.
func TrimSecret(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

// StdinSecretReader returns a ReadSecret function reading from in.
//
// When in is a terminal, echo is disabled while typing: a secret visible on
// screen ends up in scrollback, in a screen share, or in a screenshot. When in is
// a pipe, the value is read straight through, which is the normal path —
// `pbpaste | keyward add name` keeps the value out of shell history too.
//
// golang.org/x/term is the sole dependency in this project. Disabling echo means
// termios ioctls, and hand-rolling those would be more code, less portable, and
// considerably harder to review than one function from a Go-team package.
func StdinSecretReader(in *os.File, prompt io.Writer) func() ([]byte, error) {
	return func() ([]byte, error) {
		fd := int(in.Fd())

		if !term.IsTerminal(fd) {
			b, err := io.ReadAll(in)
			if err != nil {
				return nil, err
			}
			return TrimSecret(b), nil
		}

		fmt.Fprint(prompt, "Value (not echoed): ")
		b, err := term.ReadPassword(fd)
		// ReadPassword swallows the newline the user typed, so supply one or the
		// next output lands on the same line.
		fmt.Fprintln(prompt)
		if err != nil {
			return nil, err
		}
		return TrimSecret(b), nil
	}
}
