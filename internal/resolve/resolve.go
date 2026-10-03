// Package resolve turns an environment containing cap:// references into one
// containing real values.
//
// This is the step that makes the whole design work: config on disk holds only
// references, and values appear for exactly as long as one command needs them.
package resolve

import (
	"fmt"
	"sort"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/vault"
)

// Resolver resolves references against a vault.
type Resolver struct {
	store vault.Store
}

// New returns a Resolver reading from store.
func New(store vault.Store) *Resolver {
	return &Resolver{store: store}
}

// Result is the outcome of a successful resolution.
type Result struct {
	// Env is the resolved environment, ready to hand to a child process. It
	// contains plaintext secrets: do not log it, write it, or keep it.
	Env []string

	// Resolved names the secrets that were used, canonical and sorted. It holds
	// no values and is safe to log — this is what an audit record is built from.
	Resolved []string
}

// Failure describes one reference that could not be resolved.
type Failure struct {
	// Key is the environment variable holding the reference.
	Key string

	// Ref is the reference exactly as written, so a caller can suggest a fix
	// without re-reading the environment.
	Ref string

	// Err is the underlying cause: vault.ErrNotFound, vault.ErrDenied, or a name
	// validation error from the handle package.
	Err error
}

// Error reports every reference that could not be resolved.
//
// Failing on the first problem would make a user fix one reference, rerun, and
// meet the next. All failures are collected instead.
type Error struct {
	Failures []Failure
}

func (e *Error) Error() string {
	if len(e.Failures) == 1 {
		f := e.Failures[0]
		return fmt.Sprintf("%s=%s: %v", f.Key, f.Ref, f.Err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d references could not be resolved:", len(e.Failures))
	for _, f := range e.Failures {
		fmt.Fprintf(&b, "\n  %s=%s: %v", f.Key, f.Ref, f.Err)
	}
	return b.String()
}

// Unwrap exposes the causes so errors.Is finds vault.ErrNotFound and friends
// through the aggregate.
func (e *Error) Unwrap() []error {
	errs := make([]error, len(e.Failures))
	for i, f := range e.Failures {
		errs[i] = f.Err
	}
	return errs
}

// Env resolves every reference in env and returns the resulting environment.
//
// Entries that are not references pass through byte for byte, in order,
// including duplicates and anything that is not shaped like KEY=VALUE. Only a
// value beginning with the exact prefix cap:// is touched.
//
// Resolution is all or nothing. A partly resolved environment would run a command
// with some values real and some still references, which produces an
// authentication failure with no visible cause — precisely the confusion keyward
// exists to remove. On any failure, Env returns a zero Result and an *Error
// listing every reference that could not be resolved.
func (r *Resolver) Env(env []string) (Result, error) {
	out := make([]string, len(env))
	// One entry per distinct secret, so two variables referencing the same name
	// cost one lookup. With the Keychain each lookup is a syscall, and may one day
	// be a prompt.
	seen := make(map[string]string)
	var failures []Failure

	for i, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !handle.IsRef(value) {
			out[i] = entry
			continue
		}

		// The value claims to be a reference, so from here it is never passed
		// through as a literal. A malformed one is an error, not a value.
		h, err := handle.Parse(value)
		if err != nil {
			failures = append(failures, Failure{Key: key, Ref: value, Err: err})
			continue
		}

		resolved, cached := seen[h.Name]
		if !cached {
			secret, err := r.store.Get(h.Name)
			if err != nil {
				failures = append(failures, Failure{Key: key, Ref: value, Err: err})
				continue
			}
			// Converting to a string makes the value unzeroable: Go strings are
			// immutable, so vault.Secret.Destroy has nothing left to clear here.
			// Accepted rather than worked around, because an environment for
			// exec is []string at the OS boundary regardless. It costs little in
			// practice: syscall.Exec replaces the process image, discarding this
			// heap entirely.
			resolved = string(secret.Bytes())
			seen[h.Name] = resolved
		}
		out[i] = key + "=" + resolved
	}

	if len(failures) > 0 {
		return Result{}, &Error{Failures: failures}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)

	return Result{Env: out, Resolved: names}, nil
}
