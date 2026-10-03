package cli_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/veilux-lab/keyward/internal/cli"
)

func TestTrimSecret(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no newline", "token", "token"},
		{"one newline", "token\n", "token"},
		{"carriage return", "token\r\n", "token"},
		{"only the last newline", "token\n\n", "token\n"},
		{"internal newlines kept", "line1\nline2\n", "line1\nline2"},
		{"empty", "", ""},
		{"only a newline", "\n", ""},
		{"lone carriage return kept", "token\r", "token\r"},
		{"trailing space kept", "token \n", "token "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(cli.TrimSecret([]byte(tt.in))); got != tt.want {
				t.Errorf("TrimSecret(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The piped path is the normal one — `pbpaste | keyward add name` — and it is
// testable without a terminal. The echo-disabled branch needs a real tty and is
// left to manual use.
func TestStdinSecretReaderFromPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	go func() {
		defer w.Close()
		w.WriteString(token + "\n")
	}()

	var prompt bytes.Buffer
	read := cli.StdinSecretReader(r, &prompt)

	got, err := read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != token {
		t.Errorf("read %q, want %q with the newline trimmed", got, token)
	}
	// A pipe must not be prompted at, or the prompt would end up in whatever is
	// capturing output.
	if prompt.Len() != 0 {
		t.Errorf("prompted on a non-terminal: %q", prompt.String())
	}
}
