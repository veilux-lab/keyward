package vault

import (
	"errors"
	"strings"
	"testing"
)

// The status mapping is the whole reason Keychain failures are legible. If
// errSecItemNotFound did not map to ErrNotFound, every miss would surface as an
// unknown error and callers could not tell "no such secret" from "the Keychain
// is broken".
//
// Constant values were verified against Security/Security.h rather than recalled.
func TestStatusError(t *testing.T) {
	tests := []struct {
		name    string
		status  int32
		wantErr error // nil means "no sentinel, but must still be an error"
		wantNil bool
	}{
		{"success", statusSuccess, nil, true},
		{"item not found", statusItemNotFound, ErrNotFound, false},
		{"duplicate item", statusDuplicateItem, ErrExists, false},
		{"auth failed", statusAuthFailed, ErrDenied, false},
		{"interaction not allowed", statusInteractionNotAllowed, ErrDenied, false},
		{"user canceled", statusUserCanceled, ErrDenied, false},
		{"missing entitlement", statusMissingEntitlement, ErrDenied, false},
		{"bad param", statusParam, nil, false},
		{"unknown code", -99999, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := statusError("get", "splunk-mcp-token", tt.status)

			if tt.wantNil {
				if err != nil {
					t.Fatalf("statusError(%d) = %v, want nil", tt.status, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("statusError(%d) = nil, want an error", tt.status)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("statusError(%d) = %v, want errors.Is(_, %v)", tt.status, err, tt.wantErr)
			}
		})
	}
}

// A failure that cannot be matched to a sentinel must still be diagnosable, or
// debugging becomes guesswork against a closed API.
func TestStatusErrorIsDiagnosable(t *testing.T) {
	err := statusError("put", "splunk-mcp-token", -99999)
	msg := err.Error()

	for _, want := range []string{"put", "splunk-mcp-token", "-99999"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// Sentinel errors must stay distinguishable from each other. A single wrapped
// chain that satisfied several would make callers' branches silently wrong.
func TestStatusErrorSentinelsAreDistinct(t *testing.T) {
	notFound := statusError("get", "n", statusItemNotFound)
	exists := statusError("put", "n", statusDuplicateItem)
	denied := statusError("get", "n", statusAuthFailed)

	if errors.Is(notFound, ErrExists) || errors.Is(notFound, ErrDenied) {
		t.Error("ErrNotFound also matches another sentinel")
	}
	if errors.Is(exists, ErrNotFound) || errors.Is(exists, ErrDenied) {
		t.Error("ErrExists also matches another sentinel")
	}
	if errors.Is(denied, ErrNotFound) || errors.Is(denied, ErrExists) {
		t.Error("ErrDenied also matches another sentinel")
	}
}
