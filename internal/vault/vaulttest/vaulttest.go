// Package vaulttest provides the contract suite that every vault.Store
// implementation must satisfy.
//
// It exists so the in-memory fake and the real Keychain store are held to
// exactly the same behaviour. The cgo store cannot be unit tested, but it can be
// run against this suite as a build-tagged integration test — which is what keeps
// the untestable layer honest.
package vaulttest

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/vault"
)

// prefix namespaces every name the suite touches, so running against a real
// Keychain cannot collide with or destroy a genuine entry.
const prefix = "kwtest-"

// Run exercises the Store contract. newStore must return a usable store; it is
// called once per subtest so implementations may return a fresh instance.
func Run(t *testing.T, newStore func(t *testing.T) vault.Store) {
	t.Helper()

	t.Run("Roundtrip", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "roundtrip")
		want := []byte("eyJraWQiOiJzcGx1bmsi")

		if err := s.Put(name, vault.NewSecret(want), ""); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(name)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got.Bytes()) != string(want) {
			t.Errorf("Get returned %d bytes, want the stored value", got.Len())
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "missing")
		if _, err := s.Get(name); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("Get on absent name = %v, want ErrNotFound", err)
		}
	})

	// Put must never silently clobber a credential. Overwriting is Replace's job,
	// so a caller has to say which it means.
	t.Run("PutExisting", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "exists")
		if err := s.Put(name, vault.NewSecret([]byte("first")), ""); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Put(name, vault.NewSecret([]byte("second")), ""); !errors.Is(err, vault.ErrExists) {
			t.Fatalf("second Put = %v, want ErrExists", err)
		}
		got, err := s.Get(name)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got.Bytes()) != "first" {
			t.Error("a rejected Put modified the stored value")
		}
	})

	t.Run("Replace", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "replace")
		if err := s.Put(name, vault.NewSecret([]byte("old")), ""); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Replace(name, vault.NewSecret([]byte("new")), ""); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		got, err := s.Get(name)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got.Bytes()) != "new" {
			t.Error("Replace did not update the stored value")
		}
	})

	t.Run("ReplaceMissing", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "replace-missing")
		if err := s.Replace(name, vault.NewSecret([]byte("v")), ""); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("Replace on absent name = %v, want ErrNotFound", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "delete")
		if err := s.Put(name, vault.NewSecret([]byte("v")), ""); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete(name); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.Get(name); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("Get after Delete = %v, want ErrNotFound", err)
		}
		if err := s.Delete(name); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("second Delete = %v, want ErrNotFound", err)
		}
	})

	t.Run("EntriesAreSorted", func(t *testing.T) {
		s := newStore(t)
		names := []string{reserve(t, s, "list-c"), reserve(t, s, "list-a"), reserve(t, s, "list-b")}
		for _, n := range names {
			if err := s.Put(n, vault.NewSecret([]byte("v")), ""); err != nil {
				t.Fatalf("Put(%s): %v", n, err)
			}
		}
		got, err := s.Entries()
		if err != nil {
			t.Fatalf("Entries: %v", err)
		}

		var ours []string
		for _, e := range got {
			for _, want := range names {
				if e.Name == want {
					ours = append(ours, e.Name)
				}
			}
		}
		if len(ours) != len(names) {
			t.Fatalf("Entries returned %d of the %d stored names: %v", len(ours), len(names), ours)
		}
		if !sort.StringsAreSorted(ours) {
			t.Errorf("Entries is not sorted: %v", ours)
		}
	})

	// A note records where a value came from, so keyward can later tell an entry
	// whose source no longer references it from one added by hand on purpose.
	// Values are never involved.
	t.Run("Notes", func(t *testing.T) {
		s := newStore(t)
		withNote := reserve(t, s, "note-present")
		withoutNote := reserve(t, s, "note-absent")

		const note = "/Users/someone/.zshrc:42"
		if err := s.Put(withNote, vault.NewSecret([]byte("v")), note); err != nil {
			t.Fatalf("Put with a note: %v", err)
		}
		if err := s.Put(withoutNote, vault.NewSecret([]byte("v")), ""); err != nil {
			t.Fatalf("Put without a note: %v", err)
		}

		got := entryNotes(t, s)
		if got[withNote] != note {
			t.Errorf("note for %s = %q, want %q", withNote, got[withNote], note)
		}
		if got[withoutNote] != "" {
			t.Errorf("note for %s = %q, want empty", withoutNote, got[withoutNote])
		}

		// Replace updates provenance, since the value came from somewhere new.
		const moved = "/Users/someone/.zshenv:7"
		if err := s.Replace(withNote, vault.NewSecret([]byte("v2")), moved); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if got := entryNotes(t, s); got[withNote] != moved {
			t.Errorf("note after Replace = %q, want %q", got[withNote], moved)
		}
	})

	// Notes are encoded into a flat listing, so a separator inside one must not be
	// able to split a record and mislabel another entry.
	t.Run("NotesWithSeparatorsAreNeutralised", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "note-separators")

		if err := s.Put(name, vault.NewSecret([]byte("v")), "a\nb\rc\x1fd"); err != nil {
			t.Fatalf("Put: %v", err)
		}

		entries, err := s.Entries()
		if err != nil {
			t.Fatalf("Entries: %v", err)
		}
		for _, e := range entries {
			if strings.ContainsAny(e.Note, "\n\r\x1f") {
				t.Errorf("note for %s still contains a separator: %q", e.Name, e.Note)
			}
		}
		if got := entryNotes(t, s)[name]; got != "a b c d" {
			t.Errorf("note = %q, want separators replaced with spaces", got)
		}
	})

	// A name is normalised the same way a reference is, so cap://TOKEN and
	// cap://token cannot become two different entries.
	t.Run("NamesAreNormalised", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "normalise")
		upper := prefixUpper(name)

		if err := s.Put(upper, vault.NewSecret([]byte("v")), ""); err != nil {
			t.Fatalf("Put(%q): %v", upper, err)
		}
		if _, err := s.Get(name); err != nil {
			t.Errorf("Get(%q) after Put(%q): %v", name, upper, err)
		}
		if err := s.Put(name, vault.NewSecret([]byte("v")), ""); !errors.Is(err, vault.ErrExists) {
			t.Errorf("Put(%q) after Put(%q) = %v, want ErrExists", name, upper, err)
		}
	})

	t.Run("RejectsInvalidNames", func(t *testing.T) {
		s := newStore(t)
		bad := []string{"", "has space", "-leading", "trailing-", "slash/name", "cap://token"}
		for _, n := range bad {
			if err := s.Put(n, vault.NewSecret([]byte("v")), ""); err == nil {
				t.Errorf("Put(%q) succeeded, want an error", n)
			}
			if _, err := s.Get(n); err == nil {
				t.Errorf("Get(%q) succeeded, want an error", n)
			}
			if err := s.Replace(n, vault.NewSecret([]byte("v")), ""); err == nil {
				t.Errorf("Replace(%q) succeeded, want an error", n)
			}
			if err := s.Delete(n); err == nil {
				t.Errorf("Delete(%q) succeeded, want an error", n)
			}
		}
	})

	// An empty secret is almost always a bug upstream, and storing one produces
	// exactly the baffling failure this tool exists to remove: a variable that is
	// present but blank, and a connect timeout with no obvious cause.
	t.Run("RejectsEmptyValue", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "empty")
		if err := s.Put(name, vault.Secret{}, ""); !errors.Is(err, vault.ErrEmptyValue) {
			t.Errorf("Put with zero Secret = %v, want ErrEmptyValue", err)
		}
		if err := s.Put(name, vault.NewSecret([]byte{}), ""); !errors.Is(err, vault.ErrEmptyValue) {
			t.Errorf("Put with empty value = %v, want ErrEmptyValue", err)
		}
	})

	// Get must hand back an independent copy, or a caller zeroing what it received
	// would quietly destroy the stored secret.
	t.Run("GetReturnsIndependentCopy", func(t *testing.T) {
		s := newStore(t)
		name := reserve(t, s, "copy")
		if err := s.Put(name, vault.NewSecret([]byte("original")), ""); err != nil {
			t.Fatalf("Put: %v", err)
		}

		first, err := s.Get(name)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		first.Destroy()

		second, err := s.Get(name)
		if err != nil {
			t.Fatalf("second Get: %v", err)
		}
		if string(second.Bytes()) != "original" {
			t.Errorf("destroying a returned secret corrupted the store: got %q", second.Bytes())
		}
	})

	// Run with -race. The resolver reads several references per command, and a
	// daemon would serve concurrent callers.
	t.Run("ConcurrentAccess", func(t *testing.T) {
		s := newStore(t)
		shared := reserve(t, s, "concurrent-shared")
		if err := s.Put(shared, vault.NewSecret([]byte("shared-value")), ""); err != nil {
			t.Fatalf("Put: %v", err)
		}

		const n = 8
		var wg sync.WaitGroup
		errs := make(chan error, n*3)

		for i := 0; i < n; i++ {
			own := reserve(t, s, fmt.Sprintf("concurrent-%d", i))
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				if err := s.Put(name, vault.NewSecret([]byte("v")), ""); err != nil {
					errs <- fmt.Errorf("Put(%s): %w", name, err)
					return
				}
				if _, err := s.Get(name); err != nil {
					errs <- fmt.Errorf("Get(%s): %w", name, err)
				}
				if err := s.Delete(name); err != nil {
					errs <- fmt.Errorf("Delete(%s): %w", name, err)
				}
			}(own)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Get(shared); err != nil {
					errs <- fmt.Errorf("Get(shared): %w", err)
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Entries(); err != nil {
					errs <- fmt.Errorf("Entries: %w", err)
				}
			}()
		}

		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// entryNotes indexes the store's notes by name, for readable assertions.
func entryNotes(t *testing.T, s vault.Store) map[string]string {
	t.Helper()
	entries, err := s.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.Name] = e.Note
	}
	return out
}

// reserve returns a namespaced name, clears any residue from an earlier run, and
// removes it again afterwards. Matters for the Keychain store, where state
// outlives the process.
func reserve(t *testing.T, s vault.Store, suffix string) string {
	t.Helper()
	name := prefix + suffix

	clear := func() {
		if err := s.Delete(name); err != nil && !errors.Is(err, vault.ErrNotFound) {
			t.Logf("cleanup of %q: %v", name, err)
		}
	}
	clear()
	t.Cleanup(clear)
	return name
}

// prefixUpper uppercases a valid name so normalisation can be observed.
func prefixUpper(name string) string {
	out := []byte(name)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - 32
		}
	}
	upper := string(out)
	// Guard the suite's own assumption: the uppercased form must still normalise
	// back to the original, or the test would be checking nothing.
	if got, err := handle.Normalize(upper); err != nil || got != name {
		panic(fmt.Sprintf("vaulttest: %q does not normalise back to %q (got %q, err %v)", upper, name, got, err))
	}
	return upper
}
