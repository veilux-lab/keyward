// Package exposure finds stored secrets where any process can read them: in the
// command line of a running program.
//
// Environments are not checked. keyward run puts secrets there on purpose, and on
// macOS reading another process's environment takes deliberate effort, where a
// command line is printed by an ordinary ps.
package exposure

import (
	"bytes"
	"encoding/binary"
	"path/filepath"

	"github.com/veilux-lab/keyward/internal/vault"
)

// Process is a running program and the arguments it was started with.
type Process struct {
	PID  int
	Args []string
}

// Exposure is a stored secret found in a program's arguments. It names the
// secret, never its value.
type Exposure struct {
	Secret  string
	PID     int
	Program string
}

// minLength skips values too short to be told apart from ordinary arguments.
const minLength = 8

// Find reports each stored secret that appears in a process's arguments.
func Find(store vault.Store, procs []Process) ([]Exposure, error) {
	entries, err := store.Entries()
	if err != nil {
		return nil, err
	}
	var found []Exposure
	for _, e := range entries {
		secret, err := store.Get(e.Name)
		if err != nil {
			return nil, err
		}
		if secret.Len() >= minLength {
			for _, p := range procs {
				if containsIn(p.Args, secret.Bytes()) {
					found = append(found, Exposure{Secret: e.Name, PID: p.PID, Program: filepath.Base(p.Args[0])})
				}
			}
		}
		secret.Destroy()
	}
	return found, nil
}

// containsIn converts each argument rather than the value, so no copy of the
// secret outlives Destroy.
func containsIn(args []string, value []byte) bool {
	for _, a := range args {
		if bytes.Contains([]byte(a), value) {
			return true
		}
	}
	return false
}

// parseArgs reads the arguments from a kern.procargs2 buffer: the argument count,
// the executable path and its padding, then the arguments. The environment that
// follows is left unread.
func parseArgs(raw []byte) ([]string, bool) {
	if len(raw) < 4 {
		return nil, false
	}
	argc := int(binary.NativeEndian.Uint32(raw))
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return nil, false
	}
	rest = bytes.TrimLeft(rest[end:], "\x00")
	args := make([]string, 0, argc)
	for len(args) < argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, false
		}
		args = append(args, string(rest[:end]))
		rest = rest[end+1:]
	}
	return args, argc > 0
}
