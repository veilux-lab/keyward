// Package doctor reports on the health of a keyward setup.
//
// It answers two questions. Does anything reference a secret that is not there —
// which breaks a command the moment it runs. And is anything stored that nothing
// references any more.
//
// The second question cannot be answered by looking at files alone. A secret might
// be referenced somewhere doctor never read, or added by hand and referenced by
// nothing on purpose. So doctor only calls something orphaned when provenance names
// a file it actually scanned and that file no longer mentions it. Everything else
// unreferenced is reported as unknown, and nothing here deletes anything.
package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nwokolo24/keyward/internal/handle"
	"github.com/nwokolo24/keyward/internal/vault"
)

// Reference is one occurrence of a cap:// reference in a file.
type Reference struct {
	Name string
	File string
	Line int
}

// Finding is a stored secret that nothing scanned refers to, with an explanation
// the reader can act on.
type Finding struct {
	vault.Entry

	// Detail says why this entry is in the list it is in. It is the difference
	// between a report someone can act on and a list of names.
	Detail string
}

// Report is the outcome of a check. It holds names and paths only, never values.
type Report struct {
	// Scanned and Absent together state the report's coverage. Without them,
	// "unreferenced" reads as "unused" — the inference that gets a credential
	// deleted.
	Scanned []string
	Absent  []string

	// Malformed and Dangling are problems: each breaks a command today.
	Malformed []Reference
	Dangling  []Reference

	// Orphaned is verifiably unused: provenance names a scanned file that no longer
	// references it.
	Orphaned []Finding

	// Unknown is unreferenced but not provably unused. Leave alone unless sure.
	Unknown []Finding

	// Referenced names secrets that are stored and used.
	Referenced []string
}

// HasProblems reports whether anything found will break a command. Orphans and
// unknowns do not count: they cost a line of output, not a failure.
func (r *Report) HasProblems() bool {
	return len(r.Dangling) > 0 || len(r.Malformed) > 0
}

// Run scans paths and compares what they reference against what is stored.
//
// A path that does not exist is recorded in Absent rather than failing: the default
// set includes files many machines will not have.
func Run(store vault.Store, paths []string) (*Report, error) {
	r := &Report{}

	// refs maps a name to every place it is referenced.
	refs := make(map[string][]Reference)
	// scanned lets provenance be judged: a file absent from this set was never
	// looked at, so it can prove nothing.
	scanned := make(map[string]bool)

	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			// Unreadable and missing are the same thing here: no evidence either way.
			r.Absent = append(r.Absent, path)
			continue
		}
		r.Scanned = append(r.Scanned, path)
		scanned[path] = true

		valid, malformed := scanReferences(path, content)
		for _, ref := range valid {
			refs[ref.Name] = append(refs[ref.Name], ref)
		}
		r.Malformed = append(r.Malformed, malformed...)
	}

	entries, err := store.Entries()
	if err != nil {
		return nil, fmt.Errorf("reading the vault: %w", err)
	}
	stored := make(map[string]bool, len(entries))
	for _, e := range entries {
		stored[e.Name] = true
	}

	// A reference with nothing behind it fails the next time the command runs.
	for name, occurrences := range refs {
		if !stored[name] {
			r.Dangling = append(r.Dangling, occurrences...)
		}
	}
	sortReferences(r.Dangling)
	sortReferences(r.Malformed)

	for _, e := range entries {
		if len(refs[e.Name]) > 0 {
			// Referenced anywhere at all is enough. Provenance pointing elsewhere just
			// means the value moved.
			r.Referenced = append(r.Referenced, e.Name)
			continue
		}
		r.classifyUnreferenced(e, scanned)
	}

	sort.Strings(r.Referenced)
	sortFindings(r.Orphaned)
	sortFindings(r.Unknown)
	return r, nil
}

// classifyUnreferenced decides whether an unreferenced entry is provably unused.
//
// The distinction is the whole point of recording provenance. Only the first case
// is a fact; the rest are absence of evidence, and treating them as the same thing
// is how a credential gets deleted because nobody looked in the right file.
func (r *Report) classifyUnreferenced(e vault.Entry, scanned map[string]bool) {
	if e.Note == "" {
		r.Unknown = append(r.Unknown, Finding{
			Entry:  e,
			Detail: "no record of where it came from, so it was probably added by hand",
		})
		return
	}

	source := sourceFile(e.Note)
	switch {
	case scanned[source]:
		r.Orphaned = append(r.Orphaned, Finding{
			Entry:  e,
			Detail: fmt.Sprintf("came from %s, which no longer references it", e.Note),
		})
	case !fileExists(source):
		r.Unknown = append(r.Unknown, Finding{
			Entry:  e,
			Detail: fmt.Sprintf("came from %s, which no longer exists", source),
		})
	default:
		r.Unknown = append(r.Unknown, Finding{
			Entry:  e,
			Detail: fmt.Sprintf("came from %s, which was not scanned", source),
		})
	}
}

// scanReferences finds every cap:// reference in content, by text rather than by
// parsing a format — which is what lets one scanner cover shell files, .env files,
// and the JSON and TOML that MCP servers use.
//
// Only the reference itself is ever extracted. The surrounding line may hold a
// credential that has not been migrated yet, and none of it is retained.
func scanReferences(path string, content []byte) (valid, malformed []Reference) {
	for i, line := range strings.Split(string(content), "\n") {
		rest := line
		for {
			at := strings.Index(rest, handle.Prefix)
			if at < 0 {
				break
			}
			rest = rest[at+len(handle.Prefix):]

			name := rest[:nameLength(rest)]
			ref := Reference{Name: name, File: path, Line: i + 1}
			if _, err := handle.Normalize(name); err != nil {
				malformed = append(malformed, ref)
			} else {
				valid = append(valid, ref)
			}
		}
	}
	return valid, malformed
}

// nameLength measures the leading run of characters a reference name may contain.
func nameLength(s string) int {
	i := 0
	for i < len(s) {
		c := s[i]
		ok := c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			break
		}
		i++
	}
	return i
}

// sourceFile strips the line number from a "path:line" note. A path may itself
// contain a colon, so only a trailing all-digit segment counts.
func sourceFile(note string) string {
	i := strings.LastIndexByte(note, ':')
	if i <= 0 {
		return note
	}
	if _, err := strconv.Atoi(note[i+1:]); err != nil {
		return note
	}
	return note[:i]
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func sortReferences(refs []Reference) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].File != refs[j].File {
			return refs[i].File < refs[j].File
		}
		return refs[i].Line < refs[j].Line
	})
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool { return f[i].Name < f[j].Name })
}

// String renders the report. Problems come first, because a dangling reference
// breaks a command now while an orphan costs a line of output.
func (r *Report) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "scanned %d file(s):\n", len(r.Scanned))
	for _, p := range r.Scanned {
		fmt.Fprintf(&b, "  %s\n", p)
	}
	if len(r.Absent) > 0 {
		fmt.Fprintf(&b, "not read (missing or unreadable):\n")
		for _, p := range r.Absent {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}

	if len(r.Dangling) > 0 {
		fmt.Fprintf(&b, "\n%d reference(s) point at secrets that are not in the vault:\n", len(r.Dangling))
		for _, d := range r.Dangling {
			fmt.Fprintf(&b, "  %s:%d  cap://%s\n      keyward add %s\n", d.File, d.Line, d.Name, d.Name)
		}
	}

	if len(r.Malformed) > 0 {
		fmt.Fprintf(&b, "\n%d malformed reference(s), which will fail when used:\n", len(r.Malformed))
		for _, m := range r.Malformed {
			fmt.Fprintf(&b, "  %s:%d  cap://%s\n", m.File, m.Line, m.Name)
		}
	}

	if len(r.Orphaned) > 0 {
		fmt.Fprintf(&b, "\n%d secret(s) whose source no longer references them:\n", len(r.Orphaned))
		for _, f := range r.Orphaned {
			fmt.Fprintf(&b, "  %s\n      %s\n      keyward rm %s\n", f.Name, f.Detail, f.Name)
		}
	}

	if len(r.Unknown) > 0 {
		fmt.Fprintf(&b, "\n%d secret(s) nothing scanned refers to. These may still be in use:\n", len(r.Unknown))
		for _, f := range r.Unknown {
			fmt.Fprintf(&b, "  %s\n      %s\n", f.Name, f.Detail)
		}
	}

	fmt.Fprintf(&b, "\n%d secret(s) stored and referenced.\n", len(r.Referenced))
	if !r.HasProblems() {
		b.WriteString("No problems found.\n")
	}
	return b.String()
}

// DefaultPaths returns the files doctor reads when none are given: the shell
// startup files, a .env in the working directory, and the config of the agents
// most likely to hold references.
//
// The list is intentionally broad. Every file added makes an "unreferenced" verdict
// more trustworthy, and a file that does not exist costs one line of output.
func DefaultPaths(home, workdir string) []string {
	rel := []string{
		".zshrc", ".zshenv", ".zprofile", ".zlogin",
		".bashrc", ".bash_profile", ".profile",
		".claude.json",
		filepath.Join(".codex", "config.toml"),
	}
	paths := make([]string, 0, len(rel)+1)
	for _, r := range rel {
		paths = append(paths, filepath.Join(home, r))
	}
	if workdir != "" {
		paths = append(paths, filepath.Join(workdir, ".env"))
	}
	return paths
}
