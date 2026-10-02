// Package restore returns reference values to explicitly selected shell files.
package restore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/nwokolo24/keyward/internal/handle"
	"github.com/nwokolo24/keyward/internal/migrate"
	"github.com/nwokolo24/keyward/internal/vault"
)

type Item struct {
	File, Variable, Name string
	Line                 int
	assignment           migrate.Assignment
}

type Issue struct {
	File, Reason string
	Line         int
}

func (issue Issue) Location() string {
	if issue.Line > 0 {
		return fmt.Sprintf("%s:%d", issue.File, issue.Line)
	}
	return issue.File
}

type Plan struct {
	Items   []Item
	Skipped []Issue
	files   []*filePlan
}

type filePlan struct {
	path     string
	original []byte
	info     os.FileInfo
	items    []Item
}

type Result struct {
	Restored []Item
	Skipped  []Issue
}

// Read lists available names without retrieving values before confirmation.
func Read(store vault.Store, paths []string) (*Plan, error) {
	p := &Plan{}
	seen := make(map[string]bool)
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			p.Skipped = append(p.Skipped, Issue{File: path, Reason: "could not locate file"})
			continue
		}
		if seen[absolute] {
			continue
		}
		seen[absolute] = true
		info, err := os.Lstat(absolute)
		if err != nil {
			p.Skipped = append(p.Skipped, Issue{File: path, Reason: "file is missing or unreadable"})
			continue
		}
		if !info.Mode().IsRegular() {
			p.Skipped = append(p.Skipped, Issue{File: path, Reason: "not a regular file; symlinks are not replaced"})
			continue
		}
		if !supported(absolute) {
			p.Skipped = append(p.Skipped, Issue{File: path, Reason: "unsupported file format; select a shell startup file, shell script, or .env file"})
			continue
		}
		content, err := os.ReadFile(absolute)
		if err != nil {
			p.Skipped = append(p.Skipped, Issue{File: path, Reason: "file is unreadable"})
			continue
		}
		f := &filePlan{path: absolute, original: content, info: info}
		handled := make(map[int]bool)
		blocked := nonAssignmentLines(content)
		for _, a := range migrate.Scan(content).Assignments {
			if blocked[a.Line] {
				continue
			}
			if !handle.IsRef(a.Value) {
				// References in a trailing comment are not assignments to restore.
				if !strings.Contains(a.Value, handle.Prefix) {
					handled[a.Line] = true
				}
				continue
			}
			handled[a.Line] = true
			h, err := handle.Parse(a.Value)
			if err != nil {
				p.Skipped = append(p.Skipped, Issue{File: absolute, Line: a.Line, Reason: "malformed reference"})
				continue
			}
			f.items = append(f.items, Item{File: absolute, Line: a.Line, Variable: a.Name, Name: h.Name, assignment: a})
		}
		for i, line := range strings.Split(string(content), "\n") {
			if !handled[i+1] && !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, handle.Prefix) {
				p.Skipped = append(p.Skipped, Issue{File: absolute, Line: i + 1, Reason: "reference uses unsupported or embedded assignment syntax"})
			}
		}
		p.files = append(p.files, f)
	}
	count := 0
	for _, f := range p.files {
		count += len(f.items)
	}
	if count == 0 {
		return p, nil
	}
	entries, err := store.Entries()
	if err != nil {
		return nil, errors.New("could not list stored names; check that the daemon is running and the Keychain is available")
	}
	available := make(map[string]bool)
	for _, entry := range entries {
		available[entry.Name] = true
	}
	for _, f := range p.files {
		kept := f.items[:0:0]
		for _, item := range f.items {
			if !available[item.Name] {
				p.Skipped = append(p.Skipped, item.issue("secret "+item.Name+" is not stored"))
				continue
			}
			kept = append(kept, item)
			p.Items = append(p.Items, item)
		}
		f.items = kept
	}
	return p, nil
}

func (p *Plan) Preview() string {
	var b strings.Builder
	b.WriteString("Restore plan (secret values hidden):\n")
	for _, item := range p.Items {
		fmt.Fprintf(&b, "  %s:%d  %s <- cap://%s\n", item.File, item.Line, item.Variable, item.Name)
	}
	for _, issue := range p.Skipped {
		fmt.Fprintf(&b, "  skip %s  %s\n", issue.Location(), issue.Reason)
	}
	fmt.Fprintf(&b, "\n%d value(s) planned; %d item(s) skipped.\n", len(p.Items), len(p.Skipped))
	return b.String()
}

// Apply is called only after approval. Failures leave their references intact.
func (p *Plan) Apply(store vault.Store) Result {
	r := Result{Skipped: append([]Issue(nil), p.Skipped...)}
	cache := make(map[string]vault.Secret)
	failed := make(map[string]string)
	defer func() {
		for _, value := range cache {
			value.Destroy()
		}
	}()
	for _, f := range p.files {
		if len(f.items) == 0 {
			continue
		}
		if !f.unchanged() {
			for _, item := range f.items {
				r.Skipped = append(r.Skipped, item.issue("file changed or became unreadable since the preview"))
			}
			continue
		}
		parsed := migrate.Scan(f.original)
		var ready []Item
		for _, item := range f.items {
			value, cached := cache[item.Name]
			if !cached && failed[item.Name] == "" {
				var err error
				value, err = store.Get(item.Name)
				if err != nil {
					failed[item.Name] = readFailure(err)
				} else {
					cache[item.Name] = value
				}
			}
			if reason := failed[item.Name]; reason != "" {
				r.Skipped = append(r.Skipped, item.issue(reason))
				continue
			}
			quoted, ok := quote(value.Bytes(), f.path)
			if !ok {
				r.Skipped = append(r.Skipped, item.issue("stored value cannot be represented safely in this file format"))
				continue
			}
			a := item.assignment
			parsed.Replace(item.Line, a.Prefix+a.Name+"="+quoted+a.Trailer)
			ready = append(ready, item)
		}
		if len(ready) == 0 {
			continue
		}
		if err := f.write(parsed.Bytes()); err != nil {
			for _, item := range ready {
				r.Skipped = append(r.Skipped, item.issue("file changed or could not be replaced; reference was not restored"))
			}
			continue
		}
		r.Restored = append(r.Restored, ready...)
	}
	return r
}

func (item Item) issue(reason string) Issue {
	return Issue{File: item.File, Line: item.Line, Reason: reason}
}

func (f *filePlan) unchanged() bool {
	info, err := os.Lstat(f.path)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(f.info, info) || info.Mode().Perm() != f.info.Mode().Perm() {
		return false
	}
	content, err := os.ReadFile(f.path)
	return err == nil && bytes.Equal(content, f.original)
}

func (f *filePlan) write(content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".keyward-restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(content); err == nil {
		err = tmp.Chmod(0o600 | (f.info.Mode().Perm() & 0o100))
	}
	if err == nil {
		err = tmp.Sync()
	}
	err = errors.Join(err, tmp.Close())
	if err != nil {
		return err
	}
	if !f.unchanged() {
		return errors.New("file changed")
	}
	return os.Rename(tmp.Name(), f.path)
}

func readFailure(err error) string {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return "secret is no longer stored"
	case errors.Is(err, vault.ErrDenied):
		return "access to the secret was denied"
	default:
		return "could not retrieve the secret"
	}
}

// The assignment scanner is line-based; quoted text and continued commands
// must not become write targets. Heredoc delimiters need a full shell parser,
// so references after one are conservatively left for manual restoration.
func nonAssignmentLines(content []byte) map[int]bool {
	blocked := make(map[int]bool)
	var quote byte
	continued, heredoc := false, false
	for line, text := range strings.Split(string(content), "\n") {
		blocked[line+1] = quote != 0 || continued || heredoc
		continued = false
		for i := 0; i < len(text) && !heredoc; i++ {
			ch := text[i]
			if ch == '\\' && quote != '\'' {
				if i == len(text)-1 {
					continued = true
				}
				i++
				continue
			}
			if quote != 0 {
				if ch == quote {
					quote = 0
				}
				continue
			}
			if ch == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t') {
				break
			}
			switch ch {
			case '\'', '"', '`':
				quote = ch
			case '<':
				if i+1 < len(text) && text[i+1] == '<' {
					heredoc = true
					blocked[line+1] = true
				}
			}
		}
	}
	return blocked
}

func dotenv(path string) bool {
	base := filepath.Base(path)
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

func supported(path string) bool {
	if dotenv(path) {
		return true
	}
	switch filepath.Base(path) {
	case ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".envrc":
		return true
	}
	switch filepath.Ext(path) {
	case "", ".sh", ".bash", ".zsh", ".rc":
		return true
	}
	return false
}

func quote(value []byte, path string) (string, bool) {
	if len(value) == 0 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return "", false
	}
	s := string(value)
	// Dotenv parsers disagree on escapes; only an ordinary single-quoted literal
	// is portable enough to restore without knowing the application's parser.
	if dotenv(path) && strings.ContainsAny(s, "'\\\r\n") {
		return "", false
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'", true
}
