// Package agents writes the instructions that tell AI agents how to work with
// references, and finds installed agents whose global instructions do not point
// at them yet.
//
// keyward never edits an agent's own instruction file. Those files belong to the
// user, so it prints the line to add instead.
package agents

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed keyward.md
var instructions []byte

// marker starts every file keyward wrote, so it never replaces one it did not.
const marker = "<!-- Written by keyward"

// Display is how the file is named to users, independent of their home path.
const Display = "~/.agents/keyward.md"

func Instructions() []byte { return bytes.Clone(instructions) }

type State int

const (
	Missing State = iota
	Current
	Outdated
	// Foreign is a file keyward did not write, or a symlink; it is left alone.
	Foreign
)

type File struct{ Path string }

func Default(home string) File {
	return File{Path: filepath.Join(home, ".agents", "keyward.md")}
}

func (f File) Status() (State, error) {
	info, err := os.Lstat(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Missing, nil
	}
	if err != nil {
		return Missing, err
	}
	if !info.Mode().IsRegular() {
		return Foreign, nil
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return Missing, err
	}
	switch {
	case bytes.Equal(data, instructions):
		return Current, nil
	case bytes.HasPrefix(data, []byte(marker)):
		return Outdated, nil
	default:
		return Foreign, nil
	}
}

// Write creates or updates the file, refusing one keyward did not write.
func (f File) Write() error {
	st, err := f.Status()
	if err != nil {
		return err
	}
	switch st {
	case Current:
		return nil
	case Foreign:
		return fmt.Errorf("%s was not written by keyward; left it alone", f.Path)
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".keyward.md-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(instructions)
	err = errors.Join(err, tmp.Chmod(0o644), tmp.Close())
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

// Remove deletes the file if keyward wrote it, reporting whether it did.
func (f File) Remove() (bool, error) {
	st, err := f.Status()
	if err != nil || (st != Current && st != Outdated) {
		return false, err
	}
	return true, os.Remove(f.Path)
}

type Agent struct {
	Name, Config string
	// Command appends the pointer to the agent's global instructions.
	Command string
}

// Claude Code imports files with @; the others are asked to read it.
var known = []struct{ name, dir, file, line string }{
	{"Claude Code", ".claude", "CLAUDE.md", "@" + Display},
	{"Codex", ".codex", "AGENTS.md", "Before running a command that needs credentials, read " + Display + "."},
	{"Gemini CLI", ".gemini", "GEMINI.md", "Before running a command that needs credentials, read " + Display + "."},
}

// Unlinked returns installed agents whose global instructions never mention the
// file. An agent counts as installed when its configuration directory exists.
func Unlinked(home string) []Agent {
	var found []Agent
	for _, k := range known {
		if info, err := os.Stat(filepath.Join(home, k.dir)); err != nil || !info.IsDir() {
			continue
		}
		config := filepath.Join(home, k.dir, k.file)
		if mentions(config) {
			continue
		}
		found = append(found, Agent{
			Name:    k.name,
			Config:  config,
			Command: fmt.Sprintf("echo '%s' >> ~/%s/%s", strings.ReplaceAll(k.line, "'", `'\''`), k.dir, k.file),
		})
	}
	return found
}

// Linked returns the agent instruction files that point at the file, which the
// user should edit once it is gone.
func Linked(home string) []string {
	var found []string
	for _, k := range known {
		if config := filepath.Join(home, k.dir, k.file); mentions(config) {
			found = append(found, config)
		}
	}
	return found
}

func mentions(config string) bool {
	data, err := os.ReadFile(config)
	return err == nil && bytes.Contains(data, []byte("keyward.md"))
}
