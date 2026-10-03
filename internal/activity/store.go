package activity

import (
	"errors"
	"time"

	"github.com/nwokolo24/keyward/internal/handle"
	"github.com/nwokolo24/keyward/internal/vault"
)

type Store struct {
	vault.Store
	Command string
	Record  func(Event)
}

func Outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, vault.ErrNotFound):
		return "not_found"
	case errors.Is(err, vault.ErrDenied):
		return "denied"
	case errors.Is(err, vault.ErrExists):
		return "exists"
	case errors.Is(err, vault.ErrEmptyValue):
		return "empty_value"
	case errors.Is(err, handle.ErrInvalidName), errors.Is(err, handle.ErrEmptyName), errors.Is(err, handle.ErrNameTooLong), errors.Is(err, handle.ErrNotHandle):
		return "invalid"
	default:
		return "error"
	}
}

func (s *Store) record(op, name string, err error, start time.Time) {
	if s.Record == nil {
		return
	}
	canonical, invalid := handle.Normalize(name)
	if err != nil || invalid != nil {
		canonical = ""
	}
	s.Record(Event{Command: s.Command, Operation: op, Name: canonical, Outcome: Outcome(err), DurationMS: time.Since(start).Milliseconds()})
}

func (s *Store) Get(name string) (vault.Secret, error) {
	start := time.Now()
	v, err := s.Store.Get(name)
	op := "get"
	if s.Command == "run" {
		op = "resolve"
	}
	s.record(op, name, err, start)
	return v, err
}
func (s *Store) Put(name string, value vault.Secret, note string) error {
	start := time.Now()
	err := s.Store.Put(name, value, note)
	s.record("put", name, err, start)
	return err
}
func (s *Store) Replace(name string, value vault.Secret, note string) error {
	start := time.Now()
	err := s.Store.Replace(name, value, note)
	s.record("replace", name, err, start)
	return err
}
func (s *Store) Delete(name string) error {
	start := time.Now()
	err := s.Store.Delete(name)
	s.record("delete", name, err, start)
	return err
}
func (s *Store) Entries() ([]vault.Entry, error) {
	start := time.Now()
	entries, err := s.Store.Entries()
	s.record("list", "", err, start)
	return entries, err
}
