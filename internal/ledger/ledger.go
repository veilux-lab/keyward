// Package ledger records what keyward changed outside its own data, so uninstall
// undoes exactly that instead of guessing where to look. It never holds a value.
package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

type Kind string

const (
	// Rewrite is a file migrate rewrote; Quotes keeps each variable's quoting.
	Rewrite Kind = "file_rewrite"
	// Link is the line keyward added to an agent's instructions, in Text.
	Link Kind = "agent_link"
	// Server is an MCP server keyward changed through its tool; Text is its scope.
	Server Kind = "mcp_server"
	// Dir is a directory keyward created, removed once it is empty.
	Dir Kind = "owned_dir"
)

type Record struct {
	Kind   Kind              `json:"kind"`
	Path   string            `json:"path"`
	Name   string            `json:"name,omitempty"`
	Text   string            `json:"text,omitempty"`
	Quotes map[string]string `json:"quotes,omitempty"`
	// Created means keyward created the file, so undoing the change may delete it.
	Created bool      `json:"created,omitempty"`
	Time    time.Time `json:"time"`
}

func (r Record) same(o Record) bool { return r.Kind == o.Kind && r.Path == o.Path && r.Name == o.Name }

type Ledger struct{ Path string }

func Default(home string) Ledger {
	return Ledger{Path: filepath.Join(home, "Library", "Application Support", "keyward", "ledger.json")}
}

// Records returns every recorded change; a missing ledger has none.
func (l Ledger) Records() ([]Record, error) {
	data, err := os.ReadFile(l.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var records []Record
	if err == nil {
		err = json.Unmarshal(data, &records)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", l.Path, err)
	}
	return records, nil
}

// Add records a change, replacing an earlier record of the same one. A rewrite
// keeps the quoting of every variable migrated from the file so far.
func (l Ledger) Add(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	return l.update(func(records []Record) []Record {
		if i := slices.IndexFunc(records, r.same); i >= 0 {
			for k, v := range records[i].Quotes {
				if _, ok := r.Quotes[k]; !ok {
					if r.Quotes == nil {
						r.Quotes = map[string]string{}
					}
					r.Quotes[k] = v
				}
			}
			records[i] = r
			return records
		}
		return append(records, r)
	})
}

// Remove forgets a change once it has been undone.
func (l Ledger) Remove(kind Kind, path, name string) error {
	target := Record{Kind: kind, Path: path, Name: name}
	return l.update(func(records []Record) []Record {
		return slices.DeleteFunc(records, target.same)
	})
}

// update rewrites the ledger under a lock, atomically, so two commands cannot
// lose each other's records.
func (l Ledger) update(change func([]Record) []Record) error {
	dir := filepath.Dir(l.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(l.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	records, err := l.Records()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(change(records), "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ledger-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(append(data, '\n'))
	if err = errors.Join(err, tmp.Chmod(0o600), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.Path)
}
