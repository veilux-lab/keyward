// Package mask hides secrets in the output of a command that keyward run starts.
//
// keyward run gives real values to one command. When that command's output goes
// somewhere other than a terminal, such as an agent's tool call, a pipe or a
// file, something other than the user reads it. So keyward stays as the
// command's parent and replaces each value it handed over, as written or in a
// common encoding, with cap://<name>#masked.
//
// Output to a terminal passes through untouched, as does anything the command
// writes to its own files or sends over the network.
package mask

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/veilux-lab/keyward/internal/handle"
)

// MinLength is the shortest value hidden. Shorter ones, like "true" or a port
// number, would replace ordinary output.
const MinLength = 8

// Secret is a value to hide and the name of the secret it belongs to.
type Secret struct {
	Name  string
	Value string
}

// Placeholder is what a hidden value of name becomes. It is not a valid
// reference, since handle.Parse refuses the #, so copying it somewhere fails
// rather than resolving.
func Placeholder(name string) string {
	return handle.Prefix + name + "#masked"
}

// Select returns the values worth hiding, sorted by name: at least MinLength
// bytes once surrounding space is trimmed, and found in none of plain, the
// environment's other values. Any program can read those without keyward, so
// hiding a value found there protects nothing and changes ordinary output, such
// as a user name inside $HOME.
func Select(values map[string]string, plain []string) []Secret {
	var out []Secret
	for name, value := range values {
		v := strings.TrimSpace(value)
		if len(v) < MinLength || slices.ContainsFunc(plain, func(p string) bool { return strings.Contains(p, v) }) {
			continue
		}
		out = append(out, Secret{Name: name, Value: value})
	}
	slices.SortFunc(out, func(a, b Secret) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// pattern is one way a secret's value can appear in output.
type pattern struct {
	text []byte
	name string
}

// others returns the values in env other than references and the secrets'.
// As for Select, a form of a secret found in one is not hidden. A value Select
// left out, too short or inside a plain one, holds none.
func others(env []string, secrets []Secret) []string {
	var out []string
	for _, e := range env {
		if _, v, ok := strings.Cut(e, "="); ok && !handle.IsRef(v) && !slices.ContainsFunc(secrets, func(s Secret) bool { return s.Value == v }) {
			out = append(out, v)
		}
	}
	return out
}

// patterns returns every form of each secret's value, each once, but none that
// a plain value holds. Where two secrets share a value, the first one names it.
func patterns(secrets []Secret, plain []string) []pattern {
	seen := map[string]bool{}
	var out []pattern
	for _, s := range secrets {
		v := []byte(strings.TrimSpace(s.Value))
		if len(v) < MinLength {
			continue
		}
		for _, form := range forms(v) {
			if !seen[string(form)] && !slices.ContainsFunc(plain, func(p string) bool { return strings.Contains(p, string(form)) }) {
				seen[string(form)] = true
				out = append(out, pattern{text: form, name: s.Name})
			}
		}
	}
	return out
}

// forms returns value as a command might print it, each once: as is, inside a
// JSON string, also one inside another, percent-encoded, quoted with
// backslashes, and inside base64.
func forms(value []byte) [][]byte {
	out := inJSON(value)
	// What each encoder leaves as is, besides letters and digits: RFC 3986 and
	// curl, Python's quote, JavaScript's encodeURIComponent, Go's PathEscape, and
	// a URL's user info in Go and in the URL standard, which Node follows.
	for _, keep := range []string{"-._~", "-._~/", "-._~!'()*", "-._~$&+:=@", "-._~$&+,;=", "-._~!$%&'()*+,"} {
		out = append(out, percent(value, keep, false, false))
	}
	out = append(out, percent(value, "-._~", true, false), percent(value, "-._~", false, true))
	// A form's fields as the URL standard encodes them, as URLSearchParams, Java's
	// URLEncoder and Ruby's encode_www_form do, and as PHP's urlencode does.
	out = append(out, percent(value, "-._*", true, false), percent(value, "-._", true, false))
	// Python's repr, PHP's var_export and Node's inspect double each backslash,
	// and some escape a single quote too.
	out = append(out, quoted(value, 0), quoted(value, '\''))
	out = append(out, inBase64(value, base64.StdEncoding)...)
	return unique(append(out, inBase64(value, base64.URLEncoding)...))
}

// inJSON returns value as is and as JSON encoders write it inside a string,
// also one inside another, each once.
func inJSON(value []byte) [][]byte {
	texts := [][]byte{value}
	if !utf8.Valid(value) {
		texts = append(texts, valid(value))
	}
	once := [][]byte{value}
	for _, text := range texts {
		once = append(once, escapes(text)...)
	}
	once = unique(once)
	// A JSON document inside a JSON string, as an MCP tool's result often has,
	// escapes the value twice, each time as any encoder may. Escaped once more,
	// the value as is reads as one of its forms above.
	var twice [][]byte
	for _, form := range once[1:] {
		twice = append(twice, escapes(form)...)
	}
	return unique(append(once, twice...))
}

// escapes returns text as JSON encoders write it inside a string.
func escapes(text []byte) [][]byte {
	var out [][]byte
	for _, e := range escapings {
		out = append(out, jsonString(text, e))
	}
	return out
}

// escaping is how a JSON encoder writes a string. With slash, / is escaped too,
// as PHP does; html holds the escapes of characters unsafe in HTML, if any; with
// ascii, so is everything beyond ASCII, as Python and PHP do; with lines, of
// that only U+2028 and U+2029, which end a line in JavaScript, as Go, Gson and
// PHP do, and a byte that is not UTF-8 is written as \ufffd, as by Go's encoder
// before json/v2; and with upper, its hex is in upper case, as .NET's is.
type escaping struct {
	slash, ascii, lines, upper bool
	html                       map[rune]string
}

// escapings are the ways JSON encoders write a string: with / escaped or not,
// what is beyond ASCII escaped, or U+2028 and U+2029 of it, or none, and with
// Go's or PHP's escapes of characters unsafe in HTML or neither, and as Gson
// and .NET's System.Text.Json do by default.
var escapings = func() []escaping {
	var out []escaping
	for _, slash := range []bool{false, true} {
		for _, html := range []map[rune]string{nil, goHTML, phpHTML} {
			for _, e := range []escaping{{}, {lines: true}, {ascii: true}} {
				e.slash, e.html = slash, html
				out = append(out, e)
			}
		}
	}
	return append(out, escaping{lines: true, html: gsonHTML}, escaping{ascii: true, upper: true, html: dotnetHTML})
}()

// unique returns texts without repeats, in order.
func unique(texts [][]byte) [][]byte {
	seen := map[string]bool{}
	return slices.DeleteFunc(texts, func(text []byte) bool {
		if seen[string(text)] {
			return true
		}
		seen[string(text)] = true
		return false
	})
}

// How JSON encoders write the characters that are unsafe in HTML: Go's by
// default, PHP's with JSON_HEX_TAG, APOS, AMP and QUOT, as Symfony uses, Gson's
// by default, and .NET's System.Text.Json's.
var (
	goHTML     = map[rune]string{'<': `\u003c`, '>': `\u003e`, '&': `\u0026`}
	phpHTML    = map[rune]string{'<': `\u003C`, '>': `\u003E`, '&': `\u0026`, '\'': `\u0027`, '"': `\u0022`}
	gsonHTML   = map[rune]string{'<': `\u003c`, '>': `\u003e`, '&': `\u0026`, '\'': `\u0027`, '=': `\u003d`}
	dotnetHTML = map[rune]string{'<': `\u003C`, '>': `\u003E`, '&': `\u0026`, '\'': `\u0027`, '"': `\u0022`, '+': `\u002B`, '`': `\u0060`}
)

// jsonString escapes value as a JSON encoder does inside a string, the way e
// says.
func jsonString(value []byte, e escaping) []byte {
	hex := `\u%04x`
	if e.upper {
		hex = `\u%04X`
	}
	var b []byte
	for i := 0; i < len(value); {
		r, n := utf8.DecodeRune(value[i:])
		escaped, unsafe := e.html[r]
		switch {
		case unsafe:
			b = append(b, escaped...)
		case r == '"' || r == '\\' || r == '/' && e.slash:
			b = append(b, '\\', byte(r))
		case r == '\n':
			b = append(b, `\n`...)
		case r == '\r':
			b = append(b, `\r`...)
		case r == '\t':
			b = append(b, `\t`...)
		case r == '\b':
			b = append(b, `\b`...)
		case r == '\f':
			b = append(b, `\f`...)
		case r < 0x20:
			b = fmt.Appendf(b, hex, r)
		case e.ascii && r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			b = fmt.Appendf(b, hex+hex, hi, lo)
		case e.ascii && r >= utf8.RuneSelf && n > 1, e.lines && (r == '\u2028' || r == '\u2029'):
			b = fmt.Appendf(b, hex, r)
		case e.lines && r == utf8.RuneError && n == 1:
			b = append(b, `\ufffd`...)
		default:
			b = append(b, value[i:i+n]...)
		}
		i += n
	}
	return b
}

// quoted escapes value as a quoted string in Python, PHP or JavaScript shows it:
// each backslash, and quote unless it is 0.
func quoted(value []byte, quote byte) []byte {
	var b []byte
	for _, c := range value {
		if c == '\\' || quote != 0 && c == quote {
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	return b
}

// valid returns value with each byte that is not UTF-8 replaced by U+FFFD, as
// Go's JSON encoder writes it.
func valid(value []byte) []byte {
	var b []byte
	for i := 0; i < len(value); {
		r, n := utf8.DecodeRune(value[i:])
		if n == 1 && r == utf8.RuneError {
			b = utf8.AppendRune(b, r)
		} else {
			b = append(b, value[i:i+n]...)
		}
		i += n
	}
	return b
}

// percent escapes value as a URL encoder does: every byte but letters, digits
// and those in keep becomes %XX, in lower case hex if lower, and a space becomes
// + if plus.
func percent(value []byte, keep string, plus, lower bool) []byte {
	hex := "0123456789ABCDEF"
	if lower {
		hex = "0123456789abcdef"
	}
	var b []byte
	for _, c := range value {
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte(keep, c) >= 0:
			b = append(b, c)
		case c == ' ' && plus:
			b = append(b, '+')
		default:
			b = append(b, '%', hex[c>>4], hex[c&15])
		}
	}
	return b
}

// inBase64 returns the characters that encode value inside base64 text,
// whatever comes before or after it, once for each of the three places it can
// start in a 3-byte group: an HTTP Basic credential, for one, puts a user name
// before the password. Characters that also encode a neighbouring byte are left
// off.
func inBase64(value []byte, enc *base64.Encoding) [][]byte {
	var out [][]byte
	for skip := range 3 {
		text := enc.EncodeToString(append(make([]byte, skip), value...))
		// Each character stands for 6 bits; keep those whose bits all belong to value.
		first, end := (8*skip+5)/6, 8*(skip+len(value))/6
		out = append(out, []byte(text[first:end]))
	}
	return out
}

// filter hides secrets in one stream of output. write returns the output that
// can be passed on at once: everything but a tail that may be the start of a
// secret, which waits for the next write, or for flush.
type filter struct {
	pats []pattern
	// heads holds the patterns by their first MinLength bytes, which each has,
	// and byFirst by their first byte, for a start shorter than that. Most places
	// in the output start no pattern, and a clear bit in seen, for a hash of the
	// bytes there, says so at once. With 16 or more of its bits for each
	// pattern, few are set.
	heads   map[uint64][]int
	seen    []uint64
	shift   uint
	byFirst [256][]int
	longest int
	// runs follows each pattern's matches in one call of find.
	runs  []run
	calls int

	// tail is the end of the input in which a secret not yet hidden may start.
	// Its first done bytes are passed on already, as written or hidden; the rest
	// are held. hiding says the output so far ends with a placeholder whose
	// secret may go on past done.
	tail   []byte
	done   int
	hiding bool
	// guess is a name recorded only because the placeholder last out, for a
	// start held at a pause, named it as the likeliest secret. A secret found in
	// its place replaces it.
	guess string

	masked map[string]bool
}

func newFilter(secrets []Secret) *filter {
	return filterFor(patterns(secrets, nil))
}

// filterFor returns a filter that hides pats, which patterns makes of secrets.
func filterFor(pats []pattern) *filter {
	f := &filter{pats: pats, heads: map[uint64][]int{}, runs: make([]run, len(pats)), masked: map[string]bool{}}
	size := max(16, bits.Len(uint(16*len(pats))))
	f.seen, f.shift = make([]uint64, 1<<size/64), uint(64-size)
	for i, p := range f.pats {
		head := binary.LittleEndian.Uint64(p.text)
		f.heads[head] = append(f.heads[head], i)
		h := f.mix(head)
		f.seen[h/64] |= 1 << (h % 64)
		f.byFirst[p.text[0]] = append(f.byFirst[p.text[0]], i)
		f.longest = max(f.longest, len(p.text))
	}
	return f
}

// mix hashes the first MinLength bytes of a pattern to a bit of seen.
func (f *filter) mix(head uint64) uint64 {
	return head * 0x9e3779b97f4a7c15 >> f.shift
}

// starting returns the patterns that may start data, which is at least
// MinLength bytes long: those that start with its first MinLength bytes.
func (f *filter) starting(data []byte) []int {
	head := binary.LittleEndian.Uint64(data)
	if h := f.mix(head); f.seen[h/64]&(1<<(h%64)) == 0 {
		return nil
	}
	return f.heads[head]
}

// holding reports whether output is waiting for more input.
func (f *filter) holding() bool {
	return len(f.tail) > f.done
}

// write takes the next input and returns what can be passed on now.
func (f *filter) write(in []byte) []byte {
	return f.decide(append(f.tail, in...), false)
}

// flush passes on the held tail when no more input has come for a while, or at
// the end. A held start of a secret long enough to give part of it away goes
// out as a placeholder, and a shorter one, most likely ordinary output, or a
// key's armour, as written. Either way, write still hides the rest of the
// secret if it follows.
func (f *filter) flush(end bool) []byte {
	out := f.decide(f.tail, true)
	if end {
		f.tail, f.done, f.hiding, f.guess = nil, 0, false, ""
	}
	return out
}

// revealing reports whether start, the first bytes of p, gives enough of a
// secret away to hide: MinLength bytes or more, or half of p, and more than the
// armour p starts with, if any, which gives nothing away.
func revealing(p *pattern, start []byte) bool {
	n := len(start)
	return n > armour(p.text) && (n >= MinLength || 2*n >= len(p.text))
}

// armour returns the length of the armour that text starts with, or 0: a PEM
// block's armour line, like -----BEGIN RSA PRIVATE KEY-----, and its line end,
// which every key or certificate of its kind starts with, and in an OpenSSH key
// its first line of base64 too. Up to the 70 characters that ssh-keygen puts
// on it, that line holds nothing secret: the format, cipher and KDF, and the
// key's type or the start of the KDF's salt.
func armour(text []byte) int {
	label, ok := bytes.CutPrefix(text, []byte("-----BEGIN "))
	if !ok {
		return 0
	}
	// A label, the five dashes that end it, and a line end.
	width := labelLength(label)
	rest, ok := bytes.CutPrefix(label[width:], []byte("-----"))
	i := slices.IndexFunc(lineEnds, func(end string) bool { return bytes.HasPrefix(rest, []byte(end)) })
	if width == 0 || !ok || i < 0 {
		return 0
	}
	end := []byte(lineEnds[i])
	n := len(text) - len(rest) + len(end)
	if line, ok := bytes.CutPrefix(text[n:], openSSH); ok {
		k := len(openSSH) + len(line) - len(bytes.TrimLeft(line, base64Chars))
		if k <= 70 && bytes.HasPrefix(text[n+k:], end) {
			n += k + len(end)
		}
	}
	return n
}

// openSSH starts the base64 of every key in OpenSSH's format.
var openSSH = []byte(base64.StdEncoding.EncodeToString([]byte("openssh-key-v1\x00")))

const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

// labelLength returns the length of the RFC 7468 label that text starts with:
// printable ASCII other than -, with a single - or space between. A \ ends it
// too, so that no escape in JSON passes for part of one.
func labelLength(text []byte) int {
	n := 0
	for i, c := range text {
		switch {
		case '!' <= c && c <= '~' && c != '-' && c != '\\':
			n = i + 1
		case (c == '-' || c == ' ') && n == i && n > 0:
			// Part of the label only if more of it follows.
		default:
			return n
		}
	}
	return n
}

// lineEnds are how a line ends in a form of a value: as written, and escaped in
// JSON once and twice.
var lineEnds = []string{"\n", "\r\n", `\n`, `\r\n`, `\\n`, `\\r\\n`}

// match is a stretch of output that shows a secret or, if guessed, may be the
// start of one, which a pause must not let out as written.
type match struct {
	start, end int
	name       string
	guessed    bool
}

// byPlace orders matches by where they start, the longest first.
func byPlace(a, b match) int { return cmp.Or(a.start-b.start, b.end-a.end) }

// decide passes on what it can of data, the tail followed by any new input.
// With final, nothing more is coming for now, so what is held goes out too.
func (f *filter) decide(data []byte, final bool) []byte {
	n, at := len(data), f.done
	ms := f.find(data, at)
	cut, _ := f.partial(data, 0)
	if final && at < n {
		ms = f.cover(data, ms, at)
	}
	var out []byte
	i := 0
stretches:
	for i < len(ms) {
		// Overlapping matches are hidden as one stretch, so no byte of any shows.
		s, e, j := ms[i].start, ms[i].end, i+1
		for ; j < len(ms) && ms[j].start < e; j++ {
			e = max(e, ms[j].end)
		}
		switch {
		case s < at && f.hiding:
			// More of a secret whose placeholder is out already.
		case s < at:
			// A secret that starts in what a pause let out as written.
			out = f.open(out, ms[i:j], s)
		case !final && cut < e && n-s < f.longest:
			// It may go on, and starts recently enough to wait for the rest.
			break stretches
		default:
			out = f.open(f.pass(out, data[at:s]), ms[i:j], s)
		}
		for _, m := range ms[i:j] {
			f.saw(m)
		}
		at, f.hiding, i = e, true, j
	}
	// What cannot be part of a secret goes out now; the rest waits.
	end := n
	if !final {
		end = cut
		if i < len(ms) {
			end = min(end, ms[i].start)
		}
	}
	if at < end {
		out, at = f.pass(out, data[at:end]), end
	}
	// Keep what a secret may yet be found in: from the first start of one.
	keep := min(at, cut)
	f.tail, f.done = slices.Clone(data[keep:]), at-keep
	return out
}

// pass puts out data as written.
func (f *filter) pass(out, data []byte) []byte {
	if len(data) > 0 {
		out, f.hiding, f.guess = append(out, data...), false, ""
	}
	return out
}

// open puts out the placeholders for a stretch of matches that starts at s: one
// for each secret that starts or carries it on, or for the likeliest, if it is
// only a start.
func (f *filter) open(out []byte, ms []match, s int) []byte {
	f.guess = ""
	names := f.shown(ms, s)
	if len(names) == 0 {
		// Only the start of a secret, held at a pause.
		if name := ms[0].name; !f.masked[name] {
			f.masked[name], f.guess = true, name
		}
		names = []string{ms[0].name}
	}
	for _, name := range names {
		out = append(out, Placeholder(name)...)
	}
	return out
}

// shown returns the names a stretch of matches that starts at s shows. A secret
// inside another's value is part of it, and not named apart. Only matches that
// end within longest bytes of s count: a stretch goes out by the time all of
// them are known, so where writes end cannot change the names.
func (f *filter) shown(ms []match, s int) []string {
	var names []string
	end := -1
	for _, m := range ms {
		if m.guessed || m.end > s+f.longest {
			continue
		}
		if end >= 0 && m.start >= end {
			break
		}
		if m.end > end {
			end = m.end
			if !slices.Contains(names, m.name) {
				names = append(names, m.name)
			}
		}
	}
	return names
}

// saw records a secret found in the output, in place of any that a pause's
// placeholder guessed there.
func (f *filter) saw(m match) {
	if m.guessed {
		return
	}
	if f.guess != "" {
		delete(f.masked, f.guess)
	}
	f.masked[m.name], f.guess = true, ""
}

// cover adds to ms, for a pause, the start of a secret at the end of data that
// must not go out as written: one that goes on from a secret hidden already,
// or that gives enough of one away. Any other start goes out as written, but
// from where it overlaps a secret found already, it is hidden with it.
func (f *filter) cover(data []byte, ms []match, at int) []match {
	n := len(data)
	for q, p := f.partial(data, 0); p != nil; q, p = f.partial(data, q+1) {
		c := q
		if r := f.revealed(data[q:]); r != nil {
			p = r
		} else if !(f.hiding && q < at) {
			k := slices.IndexFunc(ms, func(m match) bool { return m.end > q })
			if k < 0 {
				continue
			}
			c = max(q, ms[k].start)
		}
		m := match{start: c, end: n, name: p.name, guessed: true}
		k, _ := slices.BinarySearchFunc(ms, m, byPlace)
		return slices.Insert(ms, k, m)
	}
	return ms
}

// run follows one pattern's latest run of matches that overlap one another, in
// the call of find that calls counts: where it starts, where its last match
// ends, and which match stands for the rest of it once there is one, or -1.
type run struct{ calls, first, last, rest int }

// find returns where data shows a secret and ends after from, in order, from
// one pass over data however many patterns there are. In a run of one secret's
// matches that overlap one another, those ending more than longest bytes past
// its start are one match: shown leaves them out, and a run of one repeated
// character costs no more than any other output.
func (f *filter) find(data []byte, from int) []match {
	var found []match
	f.calls++
	for s := max(0, from-f.longest+1); s+MinLength <= len(data); s++ {
		for _, i := range f.starting(data[s:]) {
			p := &f.pats[i]
			e := s + len(p.text)
			if e <= from || !bytes.HasPrefix(data[s:], p.text) {
				continue
			}
			r := &f.runs[i]
			if r.calls != f.calls || s >= r.last {
				*r = run{calls: f.calls, first: s, rest: -1}
			}
			if r.rest >= 0 {
				found[r.rest].end = e
			} else {
				if e > r.first+f.longest {
					r.rest = len(found)
				}
				found = append(found, match{start: s, end: e, name: p.name})
			}
			r.last = e
		}
	}
	slices.SortFunc(found, byPlace)
	return found
}

// partial returns the first place at or after from where data ends with the
// start of a secret, and the shortest pattern it starts; or len(data) and nil.
func (f *filter) partial(data []byte, from int) (int, *pattern) {
	for start := max(from, len(data)-f.longest+1); start < len(data); start++ {
		if p := f.prefixOf(data[start:]); p != nil {
			return start, p
		}
	}
	return len(data), nil
}

// prefixOf returns the shortest pattern that data is the start of, but not the
// whole of, or nil.
func (f *filter) prefixOf(data []byte) *pattern {
	return f.shortest(data, func(*pattern) bool { return true })
}

// revealed returns the shortest pattern that data is the start of, but not the
// whole of, and gives enough of away to hide, or nil. Data that is also the
// start of another pattern of the same secret, and no longer than its armour, is
// the secret's public armour line, as -----BEGIN is of a URL-encoded key. It can
// still give away another secret's pattern that has no armour.
func (f *filter) revealed(data []byte) *pattern {
	return f.shortest(data, func(p *pattern) bool {
		return revealing(p, data) && f.shortest(data, func(q *pattern) bool {
			return q.name == p.name && len(data) <= armour(q.text)
		}) == nil
	})
}

// shortest returns the shortest pattern that data is the start of, but not the
// whole of, and that ok accepts, or nil.
func (f *filter) shortest(data []byte, ok func(*pattern) bool) *pattern {
	var found *pattern
	candidates := f.byFirst[data[0]]
	if len(data) >= MinLength {
		candidates = f.starting(data)
	}
	for _, i := range candidates {
		if p := &f.pats[i]; len(p.text) > len(data) && bytes.HasPrefix(p.text, data) && (found == nil || len(p.text) < len(found.text)) && ok(p) {
			found = p
		}
	}
	return found
}
