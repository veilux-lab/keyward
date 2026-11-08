package migrate

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

// A comment is the text of a comment line or a trailer, read for what it shows of
// the tokens in it.
type comment struct {
	text string

	// documents are where the paths of its links to documents' hosts are, as
	// [start, end).
	documents [][]int
}

// documentHosts keep documents, whose links hold IDs that look random.
var documentHosts = []string{"docs.google.com", "drive.google.com", "notion.so", "notion.site", "gist.github.com", "loom.com", "figma.com"}

// link matches a URL's host and its path, which ends where a query or fragment
// starts, as a token in either can be a real one, and at what a document's ID is
// never written with, such as a comma, a bracket, & = + @ ! * ~ $ % ^, a
// backslash or the colon of another URL's scheme, as a token joined to the link
// can follow it.
var link = regexp.MustCompile(`://([A-Za-z0-9.-]+)(/[^\s'"\x60?#,;:|()<>\[\]{}&=+@!*~$%^\\]*)`)

func readComment(text string) comment {
	c := comment{text: text}
	for _, m := range link.FindAllStringSubmatchIndex(text, -1) {
		host := strings.ToLower(text[m[2]:m[3]])
		if !slices.ContainsFunc(documentHosts, func(d string) bool { return host == d || strings.HasSuffix(host, "."+d) }) {
			continue
		}
		// The path ends where another URL's scheme starts too, as a token joined
		// to the link can run into one.
		end := m[5]
		if strings.HasPrefix(text[end:], "://") {
			for end > m[4] && isSchemeByte(text[end-1]) {
				end--
			}
		}
		c.documents = append(c.documents, []int{m[4], end})
	}
	return c
}

// isSchemeByte reports whether c can be part of a URL's scheme, as in https or s3.
func isSchemeByte(c byte) bool { return isAlnum(c) || c == '+' || c == '-' || c == '.' }

// commitPaths are the path segments a commit's hash follows in a link to it.
var commitPaths = []string{"/commit/", "/blob/", "/tree/"}

// noToken reports whether the comment shows that its token at [start, end), found
// by its randomness alone, is none: it is hex of a digest's length after its
// algorithm, as in sha256:<hex> and sha512-<hex>, a commit's hash in a link's
// path, as in /commit/<hex>, in the path of a link to a document's host, or a
// CamelCase identifier that no word for a credential comes right before, as one
// does a passphrase.
func (c comment) noToken(start, end int) bool {
	return c.hash(start, end) || c.inDocument(start, end) || camelCase(c.text[start:end]) && !holdsCredentialWord(c.wordBefore(start))
}

// inDocument reports whether [start, end) is in the path of a link to a document's
// host. The paths are in order, so a long line's are searched, not read through.
func (c comment) inDocument(start, end int) bool {
	i := sort.Search(len(c.documents), func(i int) bool { return c.documents[i][0] > start }) - 1
	return i >= 0 && end <= c.documents[i][1]
}

// minBesideDocument characters make a token beside a document's ID, whatever it
// mixes, as a key of one case and digits can: leaving out the ID, which looks like
// a key, must not leave out a key beside it.
const minBesideDocument = 30

// besideDocument returns each token of minBesideDocument characters or more in the
// comment, to be judged as any other in it is, if one of parts, found by its
// randomness alone, is in the path of a link to a document's host.
func (c comment) besideDocument(parts []clue) []clue {
	if !slices.ContainsFunc(parts, func(p clue) bool { return p.random && c.inDocument(p.start, p.end) }) {
		return nil
	}
	var found []clue
	for _, r := range runs(c.text, isTokenByte) {
		if n := r[1] - r[0]; n >= minBesideDocument {
			found = append(found, clue{start: r[0], end: r[1], label: randomLabel(n), random: true})
		}
	}
	return found
}

// wordBefore returns the last word that ends before at, as a name in CamelCase or
// snake_case splits into words: Key of apiKey, password of db_password.
func (c comment) wordBefore(at int) string {
	end := at
	for end > 0 && !isAlnum(c.text[end-1]) {
		end--
	}
	start := end
	for start > 0 && isAlnum(c.text[start-1]) {
		start--
		// A capital after a lowercase letter or a digit starts a word, as K does in
		// apiKey.
		if isUpper(c.text[start]) && start > 0 && isAlnum(c.text[start-1]) && !isUpper(c.text[start-1]) {
			break
		}
	}
	return c.text[start:end]
}

// hash reports whether the token at [start, end) is a digest after its algorithm
// or a commit's hash in a link's path.
func (c comment) hash(start, end int) bool {
	token := c.text[start:end]
	if alg, hex, ok := strings.Cut(token, "-"); ok && hexDigest(alg, hex) {
		return true
	}
	if !isHex(token) {
		return false
	}
	for _, path := range commitPaths {
		if strings.HasSuffix(c.text[:start], path) {
			return true
		}
	}
	before, ok := strings.CutSuffix(c.text[:start], ":")
	if !ok {
		return false
	}
	// The algorithm is the word before the colon, as in nginx@sha256:<hex>.
	alg := before[strings.LastIndexFunc(before, func(r rune) bool { return r > 0x7f || !isAlnum(byte(r)) })+1:]
	return hexDigest(alg, token)
}

// hexDigest reports whether hex is hex of the length of the digest alg names.
func hexDigest(alg, hex string) bool {
	size, ok := digestSizes[strings.ToLower(alg)]
	return ok && len(hex) == 2*size && isHex(hex)
}

func isHex(s string) bool {
	return s != "" && strings.Trim(s, "0123456789abcdefABCDEF") == ""
}
