// Package migrate moves secret values out of a shell rc file and leaves cap://
// references in their place.
//
// The scanner here is deliberately conservative. It rewrites a file the user did
// not write for keyward, so anything it cannot parse with certainty is left
// untouched. A missed secret stays in plaintext, which is merely the status quo;
// a mangled line breaks the user's shell, which is unforgivable in a tool whose
// entire pitch is safety.
package migrate

import (
	"fmt"
	"strings"
)

// Assignment is one simple shell variable assignment.
//
// The fields split a line into the parts needed to rewrite only the value:
//
//	Prefix     Name   Value   Trailer
//	"export "  "FOO"  "bar"   " # why"
//	│          │      │       │
//	export     FOO=   bar     # why
type Assignment struct {
	// Line is 1-based, matching what an editor shows.
	Line int

	// Prefix is the indentation and any `export` keyword, verbatim, so unusual
	// spacing survives a rewrite.
	Prefix string

	// Name is the variable name.
	Name string

	// Value is the value with quoting removed and double-quote escapes resolved.
	Value string

	// Trailer is everything after the value — spaces, a comment, a stray carriage
	// return — kept verbatim.
	Trailer string

	// Raw is the original line, without its terminator.
	Raw string
}

// File is a scanned file, able to reproduce itself byte for byte.
type File struct {
	// lines holds each line without its terminator. A CRLF file keeps the \r at
	// the end of each line, so joining with \n reproduces the original exactly.
	lines []string

	// finalNewline records whether the content ended with a newline, so one is
	// neither added nor dropped.
	finalNewline bool

	// Assignments lists every line that parsed as a simple assignment, in order.
	Assignments []Assignment

	// exported names every variable given the export attribute anywhere in the
	// file, whether by `export NAME=value` or a bare `export NAME`.
	exported map[string]bool
}

// Exported reports whether the file exports name. Forms it does not recognise,
// such as `typeset -x` or `set -a`, read as not exported: the safe direction,
// since that only ever leaves a value in place.
func (f *File) Exported(name string) bool { return f.exported[name] }

// Scan parses content. It never fails: anything unrecognised is simply not
// reported as an assignment.
func Scan(content []byte) *File {
	f := &File{exported: make(map[string]bool)}
	if len(content) == 0 {
		return f
	}

	s := string(content)
	f.finalNewline = strings.HasSuffix(s, "\n")
	if f.finalNewline {
		s = s[:len(s)-1]
	}
	f.lines = strings.Split(s, "\n")

	for i, line := range f.lines {
		if a, ok := parseAssignment(line); ok {
			a.Line = i + 1
			f.Assignments = append(f.Assignments, a)
			if strings.TrimSpace(a.Prefix) == "export" {
				f.exported[a.Name] = true
			}
			continue
		}
		for _, name := range parseBareExport(line) {
			f.exported[name] = true
		}
	}
	return f
}

// parseBareExport returns the names in `[indent]export NAME [NAME...] [# comment]`.
// Any other word, such as a flag, means the line is not understood and yields none.
func parseBareExport(line string) []string {
	rest, ok := cutWord(strings.TrimLeft(line, " \t"), "export")
	if !ok {
		return nil
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	names := strings.Fields(rest)
	for _, n := range names {
		if name, after, ok := cutName(n); !ok || after != "" || name == "" {
			return nil
		}
	}
	return names
}

// Bytes reproduces the file. With no calls to Replace, the result is identical to
// what Scan was given.
func (f *File) Bytes() []byte {
	if len(f.lines) == 0 {
		return nil
	}
	out := strings.Join(f.lines, "\n")
	if f.finalNewline {
		out += "\n"
	}
	return []byte(out)
}

// Replace swaps the content of a 1-based line.
//
// It panics on a line outside the file. That can only happen through a
// programming error, and silently ignoring it would let a plan report success
// while changing nothing.
func (f *File) Replace(line int, text string) {
	if line < 1 || line > len(f.lines) {
		panic(fmt.Sprintf("migrate: Replace line %d outside file of %d lines", line, len(f.lines)))
	}
	f.lines[line-1] = text
}

// Rewritten returns the line that would replace a's, referencing refName.
//
// The value is always single quoted. Single quotes suppress every form of shell
// expansion, so the reference reaches keyward exactly as written no matter what
// the original quoting was.
func (a Assignment) Rewritten(refName string) string {
	return a.Prefix + a.Name + "='cap://" + refName + "'" + a.Trailer
}

// parseAssignment recognises `[indent][export ]NAME=VALUE[trailer]`.
//
// Returns false for anything else, including commented lines, multiple
// assignments on one line, unterminated quotes, and `+=` appends.
func parseAssignment(line string) (Assignment, bool) {
	rest := line

	indent := leadingSpace(rest)
	rest = rest[len(indent):]

	// A comment, or nothing at all.
	if rest == "" || rest[0] == '#' {
		return Assignment{}, false
	}

	prefix := indent
	if after, ok := cutWord(rest, "export"); ok {
		// `export` must be followed by whitespace, which cutWord guarantees, and
		// that whitespace belongs to the prefix so odd spacing survives.
		space := leadingSpace(after)
		prefix += rest[:len(rest)-len(after)] + space
		rest = after[len(space):]
	}

	name, rest, ok := cutName(rest)
	if !ok {
		return Assignment{}, false
	}

	// `=` and nothing else. `+=` is an append, whose semantics keyward does not
	// model, so it is left alone.
	if rest == "" || rest[0] != '=' {
		return Assignment{}, false
	}
	rest = rest[1:]

	value, trailer, ok := cutValue(rest)
	if !ok {
		return Assignment{}, false
	}

	return Assignment{
		Prefix:  prefix,
		Name:    name,
		Value:   value,
		Trailer: trailer,
		Raw:     line,
	}, true
}

// cutValue reads a quoted or bare value and returns it with whatever follows.
//
// Anything after the value must be whitespace, optionally then a comment.
// A second token means something is going on that this parser does not model —
// `export A=1 B=2`, or an unquoted value containing a space — so it declines.
func cutValue(s string) (value, trailer string, ok bool) {
	switch {
	case s == "":
		return "", "", true

	case s[0] == '\'':
		// Shell single quotes are literal: no escapes, ends at the next quote.
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", "", false
		}
		value, trailer = s[1:1+end], s[end+2:]

	case s[0] == '"':
		value, trailer, ok = cutDoubleQuoted(s)
		if !ok {
			return "", "", false
		}

	default:
		// Bare value: ends at whitespace or the start of a comment.
		end := strings.IndexAny(s, " \t\r#")
		if end < 0 {
			return s, "", true
		}
		value, trailer = s[:end], s[end:]
	}

	if !isTrailer(trailer) {
		return "", "", false
	}
	return value, trailer, true
}

// cutDoubleQuoted reads a double-quoted value, resolving \" and \\ the way the
// shell does. Other backslash sequences are left as written.
func cutDoubleQuoted(s string) (value, trailer string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			b.WriteByte('\\')
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", false // unterminated
}

// isTrailer reports whether what follows a value is only whitespace and possibly
// a comment.
func isTrailer(s string) bool {
	t := strings.TrimLeft(s, " \t\r")
	if t == "" {
		return true
	}
	// A comment must be separated from the value, or `FOO=bar#baz` would be read
	// as `bar` plus a comment rather than the single word it is.
	return t[0] == '#' && len(s) > len(t)
}

// cutName reads a shell variable name: a letter or underscore, then letters,
// digits, and underscores.
func cutName(s string) (name, rest string, ok bool) {
	if s == "" || !isNameStart(s[0]) {
		return "", s, false
	}
	i := 1
	for i < len(s) && isNameByte(s[i]) {
		i++
	}
	return s[:i], s[i:], true
}

func leadingSpace(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// cutWord removes word from the front of s if it is there as a whole word,
// meaning it is followed by whitespace.
func cutWord(s, word string) (rest string, ok bool) {
	if !strings.HasPrefix(s, word) {
		return s, false
	}
	rest = s[len(word):]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return s, false
	}
	return rest, true
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameByte(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}
