package vault_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

const probe = "ghp_liveLookingTokenValue123"

// The whole point of a Secret type rather than a []byte is that no formatting
// verb, and no accidental log line, can print the value. Every verb fmt might
// reach for is checked, in the shapes a value actually travels in.
func TestSecretNeverFormatsItsValue(t *testing.T) {
	s := vault.NewSecret([]byte(probe))

	type wrapper struct {
		Name string
		Val  vault.Secret
	}

	cases := map[string]string{
		"%v direct":     fmt.Sprintf("%v", s),
		"%s direct":     fmt.Sprintf("%s", s),
		"%q direct":     fmt.Sprintf("%q", s),
		"%+v direct":    fmt.Sprintf("%+v", s),
		"%#v direct":    fmt.Sprintf("%#v", s),
		"%v pointer":    fmt.Sprintf("%v", &s),
		"%v in struct":  fmt.Sprintf("%v", wrapper{Name: "splunk", Val: s}),
		"%+v in struct": fmt.Sprintf("%+v", wrapper{Name: "splunk", Val: s}),
		"%v in slice":   fmt.Sprintf("%v", []vault.Secret{s, s}),
		"%v in map":     fmt.Sprintf("%v", map[string]vault.Secret{"k": s}),
		"print":         fmt.Sprint(s),
		"println":       fmt.Sprintln(s),
	}

	for name, out := range cases {
		if strings.Contains(out, probe) {
			t.Errorf("%s leaked the value: %s", name, out)
		}
		if !strings.Contains(out, vault.Redacted) {
			t.Errorf("%s = %q, want it to contain %q", name, out, vault.Redacted)
		}
	}
}

// Audit records and error payloads get marshalled. A Secret must not ride along.
func TestSecretMarshalsRedacted(t *testing.T) {
	s := vault.NewSecret([]byte(probe))

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if strings.Contains(string(b), probe) {
		t.Errorf("Marshal leaked the value: %s", b)
	}

	b, err = json.Marshal(struct {
		Name  string       `json:"name"`
		Value vault.Secret `json:"value"`
	}{"splunk-mcp-token", s})
	if err != nil {
		t.Fatalf("Marshal of struct returned error: %v", err)
	}
	if strings.Contains(string(b), probe) {
		t.Errorf("Marshal of struct leaked the value: %s", b)
	}
}

func TestSecretBytes(t *testing.T) {
	s := vault.NewSecret([]byte(probe))
	if got := string(s.Bytes()); got != probe {
		t.Errorf("Bytes() = %q, want %q", got, probe)
	}
	if got, want := s.Len(), len(probe); got != want {
		t.Errorf("Len() = %d, want %d", got, want)
	}
}

// NewSecret must copy, so a caller reusing or zeroing its own buffer cannot
// silently corrupt a stored secret.
func TestNewSecretCopiesInput(t *testing.T) {
	buf := []byte(probe)
	s := vault.NewSecret(buf)

	for i := range buf {
		buf[i] = 'x'
	}

	if got := string(s.Bytes()); got != probe {
		t.Errorf("mutating the input changed the secret: got %q, want %q", got, probe)
	}
}

func TestSecretDestroyZeroes(t *testing.T) {
	s := vault.NewSecret([]byte(probe))
	b := s.Bytes()
	s.Destroy()

	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not zeroed after Destroy: %q", i, c)
		}
	}
	if s.Len() != 0 {
		t.Errorf("Len() = %d after Destroy, want 0", s.Len())
	}
}

// A zero Secret turns up wherever a lookup failed. It must be inert, not a panic
// waiting to happen in an error path.
func TestZeroSecretIsSafe(t *testing.T) {
	var s vault.Secret

	if s.Bytes() != nil {
		t.Errorf("Bytes() = %v, want nil", s.Bytes())
	}
	if s.Len() != 0 {
		t.Errorf("Len() = %d, want 0", s.Len())
	}
	if got := fmt.Sprintf("%v", s); !strings.Contains(got, vault.Redacted) {
		t.Errorf("%%v = %q, want it to contain %q", got, vault.Redacted)
	}
	s.Destroy() // must not panic
	if !s.IsZero() {
		t.Error("IsZero() = false, want true")
	}
}

func TestSecretEqual(t *testing.T) {
	a := vault.NewSecret([]byte("same-value"))
	b := vault.NewSecret([]byte("same-value"))
	c := vault.NewSecret([]byte("other-value"))
	short := vault.NewSecret([]byte("same"))
	var zero vault.Secret

	tests := []struct {
		name string
		x, y vault.Secret
		want bool
	}{
		{"identical", a, b, true},
		{"different", a, c, false},
		{"different lengths", a, short, false},
		{"zero and zero", zero, vault.Secret{}, true},
		{"zero and value", zero, a, false},
		{"value and zero", a, zero, false},
	}
	for _, tt := range tests {
		if got := tt.x.Equal(tt.y); got != tt.want {
			t.Errorf("%s: Equal() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
