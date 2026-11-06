package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
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
// Disabling echo means termios ioctls, so this uses golang.org/x/term rather than
// hand-rolled ioctls, which would be more code and harder to review.
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

		fmt.Fprint(prompt, "Value (not echoed, one line; pipe longer ones: pbpaste | keyward add NAME): ")
		b, err := term.ReadPassword(fd)
		// ReadPassword swallows the newline the user typed, so supply one or the
		// next output lands on the same line.
		fmt.Fprintln(prompt)
		if err != nil {
			return nil, err
		}
		// ReadPassword stops at the first newline, and the terminal holds at most
		// 1023 bytes of a line. Whatever is left of a paste would reach the shell
		// as commands, so it is read away here and nothing is stored.
		if n, err := drainTerminal(fd); err != nil || n > 0 || cutOff(len(b)) {
			clear(b)
			return nil, errors.New("nothing was stored: the paste had more than one line or was too long for the hidden prompt, " +
				"and the rest was discarded so your shell does not run it. Pipe it instead, for example: pbpaste | keyward add NAME")
		}
		return TrimSecret(b), nil
	}
}

// maxLine is the most a macOS terminal keeps of one line (MAX_INPUT minus the
// newline); it silently drops the rest, newline included.
const maxLine = 1023

// cutOff reports a value from the hidden prompt that the terminal may have cut.
func cutOff(n int) bool { return n >= maxLine }

// drainTerminal reads away anything still queued on the terminal, in raw mode so
// an unfinished last line is caught too.
func drainTerminal(fd int) (int, error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return 0, err
	}
	defer term.Restore(fd, state)
	return drain(fd, 500*time.Millisecond)
}

// drain reads and discards fd's input until it has been quiet for quiet, and
// reports how many bytes it read.
func drain(fd int, quiet time.Duration) (int, error) {
	buf := make([]byte, 4096)
	defer clear(buf)
	total := 0
	for {
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, int(quiet.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || ready == 0 {
			return total, err
		}
		n, err := unix.Read(fd, buf)
		if n <= 0 || err != nil {
			return total, err
		}
		total += n
	}
}
