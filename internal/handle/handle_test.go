package handle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nwokolo24/keyward/internal/handle"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantName string
	}{
		{"simple", "cap://token", "token"},
		{"hyphens", "cap://splunk-mcp-token", "splunk-mcp-token"},
		{"underscores", "cap://github_token", "github_token"},
		{"dots", "cap://db.primary", "db.primary"},
		{"digits", "cap://token2", "token2"},
		{"single char", "cap://a", "a"},
		{"uppercase normalized", "cap://SPLUNK_MCP_TOKEN", "splunk_mcp_token"},
		{"mixed case normalized", "cap://Db.Primary", "db.primary"},
		{"max length", handle.Prefix + strings.Repeat("a", handle.MaxNameLen), strings.Repeat("a", handle.MaxNameLen)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := handle.Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tt.in, err)
			}
			if h.Name != tt.wantName {
				t.Errorf("Parse(%q).Name = %q, want %q", tt.in, h.Name, tt.wantName)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		// Not a handle at all: the caller should treat these as literal values.
		{"empty", "", handle.ErrNotHandle},
		{"bare name", "splunk-mcp-token", handle.ErrNotHandle},
		{"other scheme", "http://example.com", handle.ErrNotHandle},
		{"malformed scheme", "cap:/token", handle.ErrNotHandle},
		{"uppercase scheme", "CAP://token", handle.ErrNotHandle},
		{"leading space", " cap://token", handle.ErrNotHandle},

		// Claims to be a handle but is not usable: the caller must surface these,
		// never pass them through to a program as if they were a secret value.
		{"no name", "cap://", handle.ErrEmptyName},
		{"inner space", "cap://foo bar", handle.ErrInvalidName},
		{"leading space in name", "cap:// token", handle.ErrInvalidName},
		{"trailing space", "cap://token ", handle.ErrInvalidName},
		{"slash in name", "cap://foo/bar", handle.ErrInvalidName},
		{"leading hyphen", "cap://-token", handle.ErrInvalidName},
		{"trailing hyphen", "cap://token-", handle.ErrInvalidName},
		{"leading dot", "cap://.token", handle.ErrInvalidName},
		{"trailing dot", "cap://token.", handle.ErrInvalidName},
		{"leading underscore", "cap://_token", handle.ErrInvalidName},
		{"special char", "cap://foo$bar", handle.ErrInvalidName},
		{"non ascii", "cap://tökén", handle.ErrInvalidName},
		{"newline", "cap://foo\nbar", handle.ErrInvalidName},
		{"too long", handle.Prefix + strings.Repeat("a", handle.MaxNameLen+1), handle.ErrNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handle.Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error %v", tt.in, tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Parse(%q) error = %v, want errors.Is(_, %v)", tt.in, err, tt.wantErr)
			}
		})
	}
}

// A malformed handle must still be recognised as a reference. Otherwise a typo
// like "cap://bad name" would be silently handed to a program as a literal
// value, which is exactly the leak the handle format exists to prevent.
func TestIsRef(t *testing.T) {
	refs := []string{
		"cap://token",
		"cap://",
		"cap://bad name",
		"cap://-invalid",
		handle.Prefix + strings.Repeat("a", handle.MaxNameLen+1),
	}
	for _, s := range refs {
		if !handle.IsRef(s) {
			t.Errorf("IsRef(%q) = false, want true", s)
		}
	}

	values := []string{
		"",
		"token",
		"ghp_abc123",
		"http://example.com",
		"cap:/token",
		"CAP://token",
		" cap://token",
		"prefixed-cap://token",
	}
	for _, s := range values {
		if handle.IsRef(s) {
			t.Errorf("IsRef(%q) = true, want false", s)
		}
	}
}

// Normalize is the single source of truth for what a name may be, shared by
// Parse and by the vault. If the two disagreed, a reference could resolve to a
// name the vault refuses to store.
func TestNormalize(t *testing.T) {
	valid := []struct{ in, want string }{
		{"token", "token"},
		{"splunk-mcp-token", "splunk-mcp-token"},
		{"github_token", "github_token"},
		{"db.primary", "db.primary"},
		{"SPLUNK_MCP_TOKEN", "splunk_mcp_token"},
		{"Db.Primary", "db.primary"},
		{"a", "a"},
		{strings.Repeat("a", handle.MaxNameLen), strings.Repeat("a", handle.MaxNameLen)},
	}
	for _, tt := range valid {
		got, err := handle.Normalize(tt.in)
		if err != nil {
			t.Errorf("Normalize(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	invalid := []struct {
		in      string
		wantErr error
	}{
		{"", handle.ErrEmptyName},
		{"foo bar", handle.ErrInvalidName},
		{" token", handle.ErrInvalidName},
		{"token ", handle.ErrInvalidName},
		{"foo/bar", handle.ErrInvalidName},
		{"-token", handle.ErrInvalidName},
		{"token-", handle.ErrInvalidName},
		{".token", handle.ErrInvalidName},
		{"_token", handle.ErrInvalidName},
		{"foo$bar", handle.ErrInvalidName},
		{"tökén", handle.ErrInvalidName},
		{"cap://token", handle.ErrInvalidName}, // a full reference is not a name
		{strings.Repeat("a", handle.MaxNameLen+1), handle.ErrNameTooLong},
	}
	for _, tt := range invalid {
		if _, err := handle.Normalize(tt.in); !errors.Is(err, tt.wantErr) {
			t.Errorf("Normalize(%q) error = %v, want errors.Is(_, %v)", tt.in, err, tt.wantErr)
		}
	}
}

// Parse must agree with Normalize on every name, since Parse is defined as the
// prefix check plus normalization.
func TestParseAgreesWithNormalize(t *testing.T) {
	names := []string{"token", "SPLUNK_MCP_TOKEN", "db.primary", "a-b_c.d"}
	for _, n := range names {
		want, err := handle.Normalize(n)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", n, err)
		}
		h, err := handle.Parse(handle.Prefix + n)
		if err != nil {
			t.Fatalf("Parse(%q): %v", handle.Prefix+n, err)
		}
		if h.Name != want {
			t.Errorf("Parse(%q).Name = %q, Normalize(%q) = %q", handle.Prefix+n, h.Name, n, want)
		}
	}
}

// Parse is called on values that may turn out to be real secrets rather than
// references. If ErrNotHandle embedded its input, every such call would risk
// writing a live credential into a log or error message.
func TestParseErrorsDoNotLeakInput(t *testing.T) {
	secrets := []string{
		"ghp_realLookingTokenValue",
		"sk-liveSecretKeyValue",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
	}
	for _, secret := range secrets {
		_, err := handle.Parse(secret)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", secret)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("Parse error leaked its input: %v", err)
		}
	}
}

func TestString(t *testing.T) {
	h, err := handle.Parse("cap://splunk-mcp-token")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got, want := h.String(), "cap://splunk-mcp-token"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringRoundTrip(t *testing.T) {
	// Parsing normalizes case, so round-tripping an uppercase handle yields the
	// canonical lowercase form rather than the original input.
	h, err := handle.Parse("cap://SPLUNK_MCP_TOKEN")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got, want := h.String(), "cap://splunk_mcp_token"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	again, err := handle.Parse(h.String())
	if err != nil {
		t.Fatalf("Parse of canonical form returned error: %v", err)
	}
	if again != h {
		t.Errorf("round trip changed handle: %#v != %#v", again, h)
	}
}

// A Handle must never render a secret value, only its name. This guards against
// a future field being accidentally exposed through String().
func TestStringOnlyContainsName(t *testing.T) {
	h, err := handle.Parse("cap://token")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got, want := h.String(), handle.Prefix+h.Name; got != want {
		t.Errorf("String() = %q, want exactly %q", got, want)
	}
}
