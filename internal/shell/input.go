package shell

import (
	"regexp"
	"slices"
	"strings"
)

// readsStdin reports whether a program that prints what it reads, such as cat
// or jq, would read stdin, or a descriptor it is given: one that names no
// file to read instead, or names stdin, as - does, or a descriptor, as
// /dev/fd/3 does, or that may, as "$f" may be -. A program whose options the
// check does not know is taken to read stdin, as is one whose code the check
// cannot see.
func readsStdin(name string, args []arg) bool {
	if slices.ContainsFunc(args, func(a arg) bool { _, fd := descriptor(a.lit); return a.isLit && (a.lit == "-" || fd) }) {
		return true
	}
	switch name {
	case "dd":
		for _, a := range args {
			if path, ok := strings.CutPrefix(leading(a), "if="); ok {
				_, fd := descriptor(path)
				return fd || !a.isLit && mayRead(trimText(segments(a.word), len("if=")))
			}
		}
		return true
	case "openssl":
		// openssl rand reads nothing; its other commands read stdin without -in.
		if i := slices.IndexFunc(args, func(a arg) bool { return a.lit == "-in" }); i >= 0 {
			return i+1 < len(args) && !args[i+1].isLit && mayRead(segments(args[i+1].word))
		}
		return !(len(args) > 0 && args[0].lit == "rand")
	}
	if i, ok := interpreters[name]; ok {
		return i.reads(args)
	}
	if r, ok := readers[name]; ok {
		return r.reads(args)
	}
	return true
}

// A reader is how a program that prints what it reads finds its input. Its
// operands name files, past the code that the first operand is for a program
// such as sed. Its flags are the options it takes without a value, so that
// an option's value is not taken for a file; it takes one with any other.
type reader struct {
	flags   string   // short options without a value
	long    []string // long options without a value
	code    bool     // the first operand is code, unless an option gives it
	codeBy  []string // options that give the code, as sed -e does
	pairs   []string // long options that take two values, as jq's --arg
	none    []string // options after which it reads input only if its code does, as jq -n
	rest    []string // options after which operands are arguments, as jq's --args
	assigns bool     // an operand NAME=value sets a variable, as awk's does
}

func (r reader) reads(args []arg) bool {
	var code *arg
	needCode, files, options, none, rest, stdin := r.code, 0, true, false, false, false
	for i := 0; i < len(args); i++ {
		a, text := args[i], leading(args[i])
		switch {
		case options && a.isLit && text == "--":
			options = false
		case options && len(text) > 1 && text[0] == '-':
			if !a.isLit {
				continue // an option and the expansion of its value, as -n"$N"
			}
			names, values := r.option(text)
			i += values
			for _, n := range names {
				needCode = needCode && !slices.Contains(r.codeBy, n)
				none = none || slices.Contains(r.none, n)
				rest = rest || slices.Contains(r.rest, n)
			}
		case needCode:
			needCode, code = false, &args[i]
		case rest || strings.HasPrefix(text, "+"):
			// An argument, or a count such as tail's +2.
		case r.assigns && assignment.MatchString(text):
		case !a.isLit && mayRead(segments(a.word)):
			stdin = true // a file the script names as it runs, which may be stdin
		default:
			files++
		}
	}
	if none && code != nil && code.isLit && !readsInput.MatchString(code.lit) {
		return false
	}
	return stdin || files == 0
}

// option reads a word of options, as -rn or --raw-output, and returns their
// names and how many of the words after it are their values.
func (r reader) option(w string) ([]string, int) {
	if long, ok := strings.CutPrefix(w, "--"); ok {
		name, _, inline := strings.Cut(long, "=")
		switch {
		case inline || slices.Contains(r.long, name):
			return []string{"--" + name}, 0
		case slices.Contains(r.pairs, name):
			return []string{"--" + name}, 2
		}
		return []string{"--" + name}, 1
	}
	var names []string
	for j := 1; j < len(w); j++ {
		names = append(names, "-"+w[j:j+1])
		if strings.IndexByte(r.flags, w[j]) < 0 {
			if j+1 < len(w) {
				return names, 0 // the rest of the word is the value, as in -n1
			}
			return names, 1
		}
	}
	return names, 0
}

// An interpreter runs code that an option gives it, as python3 -c CODE does,
// which reads stdin only if the code says so, or if it may be given stdin's
// path among its arguments, as "$f" may be /dev/stdin. Its flags are the
// options it takes without a value, and code the option whose value is the
// code, in the same word or the next. Any other option may make it read its
// input, as perl -n does, or give it code another way, so the check takes it
// to.
type interpreter struct {
	flags, code string
	words       []string // options that take the code as the next word, as node's -e
}

func (in interpreter) reads(args []arg) bool {
	var code []arg
	for i := 0; i < len(args); i++ {
		w := args[i].lit
		if !args[i].isLit || len(w) < 2 || w[0] != '-' || w == "--" {
			// A script, or the code's arguments.
			if slices.ContainsFunc(args[i:], func(a arg) bool { return !a.isLit && mayRead(segments(a.word)) }) {
				return true
			}
			break
		}
		if option, value, inline := strings.Cut(w, "="); slices.Contains(in.words, option) {
			switch {
			case inline:
				code = append(code, arg{lit: value, isLit: true})
			case i+1 < len(args):
				i++
				code = append(code, args[i])
			}
			continue
		}
		if strings.HasPrefix(w, "--") {
			return true
		}
	cluster:
		for j := 1; j < len(w); j++ {
			switch {
			case strings.IndexByte(in.flags, w[j]) >= 0:
			case strings.IndexByte(in.code, w[j]) < 0:
				return true
			case j+1 < len(w):
				code = append(code, arg{lit: w[j+1:], isLit: true})
				break cluster
			case i+1 < len(args):
				i++
				code = append(code, args[i])
				break cluster
			}
		}
	}
	return len(code) == 0 || slices.ContainsFunc(code, func(a arg) bool { return !a.isLit || readsInput.MatchString(a.lit) })
}

// leading is a word's text, or the literal text it starts with, if it has
// expansions.
func leading(a arg) string {
	if a.isLit {
		return a.lit
	}
	return firstText(segments(a.word))
}

// mayRead reports whether a word with expansions, as segments gives it, may
// name stdin or a descriptor, as "$f" may be - and "/dev/fd/$n" /dev/fd/0.
func mayRead(segs []segment) bool {
	return mayName(segs, "-", "/dev/stdin")
}

// mayName reports whether a word with expansions, as segments gives it, may
// name one of paths or a descriptor: whether the literal text it starts and
// ends with fits one of them or /dev/fd/N.
func mayName(segs []segment, paths ...string) bool {
	start, end := ends(segs)
	for _, path := range paths {
		if strings.HasPrefix(path, start) && strings.HasSuffix(path, end) && len(start)+len(end) <= len(path) {
			return true
		}
	}
	const fd = "/dev/fd/"
	digits := func(s string) bool { return strings.Trim(s, "0123456789") == "" }
	return (strings.HasPrefix(fd, start) || strings.HasPrefix(start, fd) && digits(start[len(fd):])) &&
		strings.HasSuffix(fd, strings.TrimRight(end, "0123456789"))
}

var (
	// readsInput is code that reads stdin, in the languages of the programs
	// that run code: input and inputs in jq, sys.stdin and input() in python,
	// <STDIN> and <> in perl, ARGF and a bare gets in ruby, and process.stdin
	// or fd 0 in node. f.readline() reads another file.
	readsInput = regexp.MustCompile(`(?i:stdin)|input|ARGF|ARGV>|(?:^|[^.\w])(?:gets|readlines?)\b|<>|\$<|/dev/fd/0|\(\s*0\s*[,)]`)

	interpreters = map[string]interpreter{
		"node":    {words: []string{"-e", "-p", "-pe", "--eval", "--print"}},
		"perl":    {flags: "chsStTuUvwWX", code: "eE"},
		"python":  {flags: "bBdEhIOPqRsSuvVx", code: "c"},
		"python3": {flags: "bBdEhIOPqRsSuvVx", code: "c"},
		"ruby":    {flags: "acdhlsSvwy", code: "e"},
	}

	grepReader = reader{flags: "abcEFGHhIiLlnoPqRrsTUuVvwxyZz0123456789", code: true,
		codeBy: []string{"-e", "-f", "--regexp", "--file"},
		long: []string{"extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp", "ignore-case",
			"no-ignore-case", "invert-match", "word-regexp", "line-regexp", "count", "color", "colour",
			"files-without-match", "files-with-matches", "only-matching", "quiet", "silent", "no-messages",
			"byte-offset", "with-filename", "no-filename", "line-number", "initial-tab", "null", "null-data",
			"text", "recursive", "dereference-recursive", "line-buffered"}}
	awkReader = reader{code: true, codeBy: []string{"-f", "--file", "-e", "--source", "-E", "--exec"}, assigns: true}

	// readers are the programs that print what they read whose options the
	// check knows. A flag is listed only if no common version of the program
	// takes a value with it, as BSD sed does with -l.
	readers = map[string]reader{
		"awk": awkReader, "gawk": awkReader, "mawk": awkReader, "nawk": awkReader,
		"grep": grepReader, "egrep": grepReader, "fgrep": grepReader,
		"base64": {flags: "dD", long: []string{"decode", "ignore-garbage"}},
		"cat": {flags: "AbeElnstTuv", long: []string{"show-all", "number-nonblank", "show-ends", "number",
			"squeeze-blank", "show-tabs", "show-nonprinting"}},
		"cut":  {flags: "nswz", long: []string{"complement", "only-delimited", "zero-terminated"}},
		"head": {flags: "qvz0123456789", long: []string{"quiet", "silent", "verbose", "zero-terminated"}},
		"jq": {flags: "abcCefhjMnrRsSV", code: true, long: []string{"ascii-output", "binary", "color-output",
			"compact-output", "exit-status", "from-file", "join-output", "monochrome-output", "null-input",
			"raw-input", "raw-output", "raw-output0", "seq", "slurp", "sort-keys", "stream", "stream-errors",
			"tab", "unbuffered", "args", "jsonargs"},
			pairs: []string{"arg", "argjson", "slurpfile", "rawfile"},
			none:  []string{"-n", "--null-input"}, rest: []string{"--args", "--jsonargs"}},
		"sed": {flags: "Eanrsuz", code: true, codeBy: []string{"-e", "-f", "--expression", "--file"},
			long: []string{"quiet", "silent", "debug", "posix", "sandbox", "follow-symlinks", "in-place",
				"null-data", "zero-terminated", "separate", "unbuffered", "regexp-extended"}},
		"sort": {flags: "bcCdfghiMmnRrsuVz", long: []string{"ignore-leading-blanks", "dictionary-order",
			"ignore-case", "general-numeric-sort", "ignore-nonprinting", "month-sort", "human-numeric-sort",
			"numeric-sort", "random-sort", "reverse", "version-sort", "check", "merge", "stable", "unique",
			"zero-terminated", "debug"}},
		"tail": {flags: "fFqrvz0123456789", long: []string{"follow", "retry", "quiet", "silent", "verbose", "zero-terminated"}},
		"uniq": {flags: "cdDiuz", long: []string{"count", "repeated", "all-repeated", "ignore-case", "unique",
			"zero-terminated", "group"}},
	}
)
