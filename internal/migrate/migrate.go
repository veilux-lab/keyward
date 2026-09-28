package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nwokolo24/keyward/internal/vault"
)

// Change is an assignment that will become a reference.
type Change struct {
	Assignment

	// RefName is the vault name the value will be stored under.
	RefName string

	// Reason is why Detect judged this a secret. Shown in the diff so a human can
	// disagree before anything is written.
	Reason string
}

// Skip is an assignment that will be left alone, and why.
type Skip struct {
	Assignment
	Reason string

	// Actionable marks a skip the user could do something about: a value that does
	// look like a secret but that keyward declined to move. Distinguished from a
	// line that simply is not a secret, because those need no attention and would
	// bury the ones that do.
	Actionable bool
}

// Plan is a proposed migration of one file. Building a plan changes nothing;
// Apply does the work.
type Plan struct {
	// Path is the file the plan describes.
	Path string

	Changes []Change
	Skips   []Skip

	// file is the parsed original, used to produce the rewritten content.
	file *File

	// original is the exact content the plan was built from, used both for the
	// backup and to detect the file changing underneath us.
	original []byte
}

// Applied reports what Apply did.
type Applied struct {
	// BackupPath is where the original was copied, empty if nothing was changed.
	BackupPath string

	// Stored lists the reference names written to the vault, sorted.
	Stored []string
}

// NewPlan examines content and decides what to move.
//
// It returns an error only for problems that make the whole file unsafe to
// migrate — a name that cannot become a reference, or two names that would
// collide on one vault entry. Anything merely uninteresting becomes a Skip.
func NewPlan(path string, content []byte) (*Plan, error) {
	f := Scan(content)
	p := &Plan{Path: path, file: f, original: content}

	// refs guards against two variables claiming one vault entry, which would
	// silently make one of them resolve to the other's value.
	refs := make(map[string]string)

	for _, a := range f.Assignments {
		d := Detect(a.Name, a.Value)
		if !d.Secret {
			p.Skips = append(p.Skips, Skip{Assignment: a, Reason: d.Reason})
			continue
		}

		// A name that cannot be represented as a reference is skipped rather than
		// fatal. It cannot collide with anything, so leaving that one line in
		// plaintext — the status quo — is better than refusing the whole file. One
		// variable called oauth_client_id_ blocked a real ~/.zshrc entirely before
		// this was a skip.
		ref, err := RefName(a.Name)
		if err != nil {
			p.Skips = append(p.Skips, Skip{
				Assignment: a,
				Reason:     "looks like a secret, but the name cannot become a reference; rename it to migrate it",
				Actionable: true,
			})
			continue
		}
		if other, taken := refs[ref]; taken {
			return nil, fmt.Errorf("%s:%d: %s and %s both map to the reference %q; rename one before migrating",
				path, a.Line, other, a.Name, ref)
		}
		refs[ref] = a.Name

		p.Changes = append(p.Changes, Change{Assignment: a, RefName: ref, Reason: d.Reason})
	}
	return p, nil
}

// Read builds a plan from a file on disk.
func Read(path string) (*Plan, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewPlan(path, content)
}

// Empty reports whether there is nothing to move.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Check consults the vault and demotes any change that conflicts with what is
// already stored, so the plan describes what will actually happen.
//
// This exists because of a sequence that turns up in real use: a variable is
// migrated, later removed from the file, then re-added with a new value. The vault
// still holds the old one. Without Check, that conflict surfaced part way through
// Apply — after the user had already approved a plan that said otherwise — and
// aborted migrations that had nothing to do with it.
//
// A name holding the identical value stays a change: the vault is already right,
// but the file still has plaintext in it that needs replacing.
//
// Call it before Diff. Apply keeps its own conflict guard for the narrow window
// between the two.
func (p *Plan) Check(store vault.Store) error {
	kept := p.Changes[:0:0]

	for _, c := range p.Changes {
		existing, err := store.Get(c.RefName)
		switch {
		case errors.Is(err, vault.ErrNotFound):
			kept = append(kept, c)
			continue
		case err != nil:
			// Never assume absent. Treating an unreadable entry as missing would
			// let Apply overwrite something it could not inspect.
			return fmt.Errorf("checking %q against the vault: %w", c.RefName, err)
		}

		proposed := vault.NewSecret([]byte(c.Value))
		same := existing.Equal(proposed)
		proposed.Destroy()
		existing.Destroy()

		if same {
			kept = append(kept, c)
			continue
		}
		p.Skips = append(p.Skips, Skip{
			Assignment: c.Assignment,
			Reason: fmt.Sprintf("the vault already holds a different value under %q; remove it with `keyward rm %s` or rename the variable",
				c.RefName, c.RefName),
			Actionable: true,
		})
	}

	p.Changes = kept
	// Skips gained entries out of order; restore file order so the plan reads top
	// to bottom.
	sort.Slice(p.Skips, func(i, j int) bool { return p.Skips[i].Line < p.Skips[j].Line })
	return nil
}

// Blocked returns the skips worth the user's attention: values that do look like
// secrets but that keyward declined to move. Used to explain a plan with nothing in
// it, where "nothing to move" on its own would hide the fact that a secret was
// deliberately left in plaintext.
func (p *Plan) Blocked() []Skip {
	var out []Skip
	for _, s := range p.Skips {
		if s.Actionable {
			out = append(out, s)
		}
	}
	return out
}

// Diff describes the plan for a human to approve.
//
// Values are never shown, only their length. The diff is printed to a terminal,
// lands in scrollback, and may be produced by an agent running keyward — printing
// the old line verbatim would spill every secret in the file at once, which is
// precisely what this tool exists to prevent.
func (p *Plan) Diff() string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s: %d value(s) to move, %d left alone\n", p.Path, len(p.Changes), len(p.Skips))

	for _, c := range p.Changes {
		fmt.Fprintf(&b, "\n@@ line %d @@ %s\n", c.Line, c.Reason)
		fmt.Fprintf(&b, "-%s%s=<%d bytes hidden>%s\n", c.Prefix, c.Name, len(c.Value), c.Trailer)
		fmt.Fprintf(&b, "+%s\n", c.Rewritten(c.RefName))
	}

	if len(p.Skips) > 0 {
		b.WriteString("\nleft alone:\n")
		width := 0
		for _, s := range p.Skips {
			if len(s.Name) > width {
				width = len(s.Name)
			}
		}
		for _, s := range p.Skips {
			fmt.Fprintf(&b, "  line %-4d %-*s  %s\n", s.Line, width, s.Name, s.Reason)
		}
	}
	return b.String()
}

// Apply stores the secrets and rewrites the file.
//
// The order is the safety property. Every secret is stored first; only then is the
// file touched. A failure while storing leaves the file and its plaintext exactly
// as they were, so nothing is lost and the command can simply be re-run. The
// reverse order would, on a failure, leave a file referencing secrets that do not
// exist with the only copies already overwritten.
func (p *Plan) Apply(store vault.Store) (*Applied, error) {
	if p.Empty() {
		return &Applied{}, nil
	}

	// The plan names line numbers. If the file moved on since it was built, those
	// numbers describe something else.
	current, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, err
	}
	if string(current) != string(p.original) {
		return nil, fmt.Errorf("%s changed since the plan was made; re-run to build a new one", p.Path)
	}

	info, err := os.Stat(p.Path)
	if err != nil {
		return nil, err
	}
	mode := info.Mode().Perm()

	stored := make([]string, 0, len(p.Changes))
	for _, c := range p.Changes {
		// Provenance: where this value came from, so a later doctor run can tell an
		// entry whose source no longer references it from one added by hand.
		note := fmt.Sprintf("%s:%d", p.Path, c.Line)
		if err := storeSecret(store, c.RefName, c.Value, note); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", p.Path, c.Line, err)
		}
		stored = append(stored, c.RefName)
	}
	sort.Strings(stored)

	backup := backupPath(p.Path, time.Now())
	if err := os.WriteFile(backup, p.original, mode); err != nil {
		return nil, fmt.Errorf("writing the backup: %w", err)
	}

	for _, c := range p.Changes {
		p.file.Replace(c.Line, c.Rewritten(c.RefName))
	}
	if err := writeAtomic(p.Path, p.file.Bytes(), mode); err != nil {
		return nil, fmt.Errorf("rewriting %s (the original is at %s): %w", p.Path, backup, err)
	}

	return &Applied{BackupPath: backup, Stored: stored}, nil
}

// storeSecret writes one value, tolerating a previous run having already done so.
//
// An existing entry holding the same value means an earlier attempt got this far,
// so the command stays re-runnable. An existing entry holding something else is a
// conflict: overwriting it could destroy a credential something else depends on.
func storeSecret(store vault.Store, name, value, note string) error {
	secret := vault.NewSecret([]byte(value))
	defer secret.Destroy()

	err := store.Put(name, secret, note)
	if err == nil {
		return nil
	}
	if !errors.Is(err, vault.ErrExists) {
		return err
	}

	existing, getErr := store.Get(name)
	if getErr != nil {
		return getErr
	}
	defer existing.Destroy()

	if existing.Equal(secret) {
		return nil
	}
	return fmt.Errorf("%q already holds a different value; remove it or rename the variable", name)
}

// backupPath names a timestamped sibling of path, so repeated runs never overwrite
// an earlier backup.
func backupPath(path string, now time.Time) string {
	return path + ".keyward-backup-" + now.UTC().Format("20060102T150405Z")
}

// writeAtomic replaces path via a temporary file in the same directory and a
// rename, so an interruption cannot leave a half-written shell config.
func writeAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".keyward-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// Remove the temporary file on any path that does not end in a rename.
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	// Flush to disk before the rename, so a crash cannot leave the new name
	// pointing at an empty or partial file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp makes the file 0600; restore the original permissions.
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	tmpName = "" // renamed, nothing to clean up
	return nil
}
