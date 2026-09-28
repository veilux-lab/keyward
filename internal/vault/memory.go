package vault

import (
	"fmt"
	"sort"
	"sync"

	"github.com/nwokolo24/keyward/internal/handle"
)

// Memory is an in-process Store, used to test everything built above the
// interface without touching the real Keychain.
//
// It is safe for concurrent use. That is not incidental: the resolver reads
// several references per command, so a Store that needed external locking would
// push that requirement onto every caller.
type Memory struct {
	mu sync.RWMutex
	m  map[string][]byte
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory {
	return &Memory{m: make(map[string][]byte)}
}

// Get implements Store.
func (s *Memory) Get(name string) (Secret, error) {
	key, err := normalize(name)
	if err != nil {
		return Secret{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.m[key]
	if !ok {
		return Secret{}, fmt.Errorf("%q: %w", key, ErrNotFound)
	}
	// NewSecret copies, so the caller cannot reach the stored bytes.
	return NewSecret(b), nil
}

// Put implements Store.
func (s *Memory) Put(name string, value Secret) error {
	key, err := checkPut(name, value)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[key]; ok {
		return fmt.Errorf("%q: %w", key, ErrExists)
	}
	s.m[key] = clone(value.Bytes())
	return nil
}

// Replace implements Store.
func (s *Memory) Replace(name string, value Secret) error {
	key, err := checkPut(name, value)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[key]; !ok {
		return fmt.Errorf("%q: %w", key, ErrNotFound)
	}
	s.m[key] = clone(value.Bytes())
	return nil
}

// Delete implements Store.
func (s *Memory) Delete(name string) error {
	key, err := normalize(name)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[key]; !ok {
		return fmt.Errorf("%q: %w", key, ErrNotFound)
	}
	// Zero before dropping the reference, matching what the real store should do.
	for i := range s.m[key] {
		s.m[key][i] = 0
	}
	delete(s.m, key)
	return nil
}

// List implements Store.
func (s *Memory) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.m))
	for k := range s.m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// Seed loads several secrets at once, for tests of higher layers that need a
// populated store. It validates everything before storing anything, so a bad
// entry cannot leave the store half filled. Existing names are overwritten.
func (s *Memory) Seed(values map[string]string) error {
	staged := make(map[string][]byte, len(values))
	for name, value := range values {
		key, err := checkPut(name, NewSecret([]byte(value)))
		if err != nil {
			return err
		}
		staged[key] = []byte(value)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, b := range staged {
		s.m[key] = clone(b)
	}
	return nil
}

// normalize canonicalises a name for use as a key.
func normalize(name string) (string, error) {
	key, err := handle.Normalize(name)
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	return key, nil
}

// checkPut validates the name and rejects an empty value. Shared so Put,
// Replace, and Seed cannot drift apart on what they accept.
func checkPut(name string, value Secret) (string, error) {
	key, err := normalize(name)
	if err != nil {
		return "", err
	}
	if value.IsZero() {
		return "", fmt.Errorf("%q: %w", key, ErrEmptyValue)
	}
	return key, nil
}

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
