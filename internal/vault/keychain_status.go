package vault

import "fmt"

// OSStatus values returned by the Security framework.
//
// Declared in Go rather than read through cgo so the mapping below can be unit
// tested without a compiler toolchain or a live Keychain. Values were verified by
// compiling against Security/Security.h, not recalled from memory — a wrong
// statusItemNotFound would mean ErrNotFound never fires and every miss looks like
// an unknown failure.
const (
	statusSuccess               int32 = 0
	statusUserCanceled          int32 = -128
	statusParam                 int32 = -50
	statusNotAvailable          int32 = -25291
	statusAuthFailed            int32 = -25293
	statusDuplicateItem         int32 = -25299
	statusItemNotFound          int32 = -25300
	statusInteractionNotAllowed int32 = -25308
	statusDecode                int32 = -26275
	statusMissingEntitlement    int32 = -34018
)

// statusError converts an OSStatus into a Go error, mapping the outcomes callers
// branch on to sentinels and leaving everything else diagnosable by code.
//
// op and name appear in the message. A value never does.
func statusError(op, name string, status int32) error {
	switch status {
	case statusSuccess:
		return nil

	case statusItemNotFound:
		return fmt.Errorf("keychain %s %q: %w", op, name, ErrNotFound)

	case statusDuplicateItem:
		return fmt.Errorf("keychain %s %q: %w", op, name, ErrExists)

	case statusUserCanceled:
		return fmt.Errorf("keychain %s %q: prompt dismissed: %w", op, name, ErrDenied)

	case statusAuthFailed:
		return fmt.Errorf("keychain %s %q: authentication failed: %w", op, name, ErrDenied)

	case statusInteractionNotAllowed:
		// Typically a locked keychain, or a process with no way to show a prompt.
		return fmt.Errorf("keychain %s %q: keychain locked or no prompt possible: %w", op, name, ErrDenied)

	case statusMissingEntitlement:
		// Expected for an unsigned binary reaching for the data protection
		// keychain. Relevant to any future biometric work.
		return fmt.Errorf("keychain %s %q: missing entitlement (OSStatus %d): %w", op, name, status, ErrDenied)

	case statusNotAvailable:
		return fmt.Errorf("keychain %s %q: no keychain available (OSStatus %d)", op, name, status)

	case statusParam:
		return fmt.Errorf("keychain %s %q: invalid parameter (OSStatus %d)", op, name, status)

	case statusDecode:
		return fmt.Errorf("keychain %s %q: could not decode the stored item (OSStatus %d)", op, name, status)

	default:
		return fmt.Errorf("keychain %s %q: unexpected OSStatus %d", op, name, status)
	}
}

// noteSeparator divides a name from its note in the flat listing the C helper
// returns. A unit separator cannot appear in a path, and SanitizeNote removes it
// from notes anyway, so a record can never be split in the wrong place.
const noteSeparator = '\x1f'

// DefaultService is the Keychain service name keyward stores items under. Each
// secret is a separate generic-password item, which is what makes the OS's
// per-item access controls available.
const DefaultService = "keyward"
