// Package agents writes the instructions that tell AI agents how to work with
// references, and finds installed agents whose global instructions do not point
// at them yet.
//
// The agents' own instruction files belong to the user: keyward adds or removes
// its one line only when asked.
package agents

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/ledger"
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

// removedNotice replaces the instructions when the daemon finds keyward's program
// deleted without `keyward uninstall`.
const removedNotice = marker + `, which replaces this file when it updates it. Keep your own notes in another file. -->
# keyward was removed without uninstalling

keyward's program was deleted (for example by ` + "`brew uninstall`" + `) without
` + "`keyward uninstall`" + `, so files may still hold ` + "`cap://`" + ` references that nothing
can resolve, and MCP servers may still try to start through keyward.

- Tell the user, rather than looking for the values.
- Suggest that they reinstall and uninstall properly, which puts the values back:
  ` + "`brew install veilux-lab/keyward/keyward && keyward uninstall`" + `
`

// WriteRemovedNotice replaces the instructions with removedNotice, if keyward
// wrote the file.
func (f File) WriteRemovedNotice() error {
	if st, err := f.Status(); err != nil || (st != Current && st != Outdated) {
		return err
	}
	return writeKeepingMode(f.Path, []byte(removedNotice))
}

// WriteRecorded is Write, recording in l the folder it had to create, so
// uninstall can remove that folder once it is empty.
func (f File) WriteRecorded(l ledger.Ledger) error {
	dir := filepath.Dir(f.Path)
	_, err := os.Lstat(dir)
	created := errors.Is(err, fs.ErrNotExist)
	if err := f.Write(); err != nil {
		return err
	}
	if created && l.Path != "" {
		return l.Add(ledger.Record{Kind: ledger.Dir, Path: dir})
	}
	return nil
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
	// Line points the agent at the instructions; Command appends it by hand.
	Line, Command string
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
			Line:    k.line,
			Command: fmt.Sprintf("echo '%s' >> ~/%s/%s", strings.ReplaceAll(k.line, "'", `'\''`), k.dir, k.file),
		})
	}
	return found
}

// Link appends the agent's line to its instructions, creating the file if it is
// missing, and reports whether it did.
func (a Agent) Link() (created bool, err error) {
	data, err := os.ReadFile(a.Config)
	created = errors.Is(err, fs.ErrNotExist)
	if err != nil && !created {
		return false, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return created, writeKeepingMode(a.Config, append(data, a.Line+"\n"...))
}

// Unlink removes the line Link added, and the file too if keyward created it and
// nothing else is left. A file without the line is left as it is.
func Unlink(config, line string, created bool) error {
	data, err := os.ReadFile(config)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(data), "\n")
	i := slices.IndexFunc(lines, func(l string) bool { return strings.TrimRight(l, "\r\n") == line })
	if i < 0 {
		return nil
	}
	rest := strings.Join(slices.Delete(lines, i, i+1), "")
	if created && strings.TrimSpace(rest) == "" {
		return os.Remove(config)
	}
	return writeKeepingMode(config, []byte(rest))
}

// writeKeepingMode replaces a file atomically, keeping its permissions.
func writeKeepingMode(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err = errors.Join(err, tmp.Chmod(mode), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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
