package migrate

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Label names what credential-shaped text looks like, in plain words: One for one
// of it and Many for several. It is built from fixed words and lengths, never from
// the text, which can be the token itself.
type Label struct {
	One, Many string

	// anyLength names several of a kind that has a length whatever their lengths,
	// as "random tokens" does, or is "" for a kind that has none.
	anyLength string
}

// countable labels a thing one counts, as "a GitHub token" is.
func countable(one string) Label {
	_, rest, _ := strings.Cut(one, " ")
	return Label{One: one, Many: rest + "s"}
}

// runOf labels a length of text, as "40 hex characters" is.
func runOf(one string) Label { return Label{One: one, Many: "runs of " + one} }

// sized gives l, which says a length, the words for several of its kind whatever
// their lengths.
func sized(l Label, anyLength string) Label {
	l.anyLength = anyLength
	return l
}

// urlLabel labels a URL that holds a password.
var urlLabel = Label{One: "a URL with a password", Many: "URLs with passwords"}

// prefixLabel labels value, which starts with the credential prefix p, as the kind
// of credential p marks, unless it is not of that kind's shape: eyJ starts any
// JSON in base64, and a PEM block can hold a certificate or a public key.
func prefixLabel(p, value string) Label {
	switch {
	case p == "eyJ" && !knownShape(p, value):
		return Label{One: "base64-encoded JSON", Many: "base64-encoded JSON"}
	case p == "-----BEGIN " && !knownShape(p, value):
		return Label{One: "a certificate or public key", Many: "certificates or public keys"}
	}
	for _, issuer := range credentialPrefixes {
		if slices.Contains(issuer.prefixes, p) {
			return countable(issuer.kind)
		}
	}
	return Label{}
}

// named labels a value whose name suggests a credential, before what in it looks
// random, if anything does.
var named = Label{One: "a value named like a credential", Many: "values named like credentials"}

// namedLabel labels a value whose name suggests a credential, with what in it
// looks random, if anything does.
func namedLabel(value string) Label {
	if l := tokenLabel(value); l != (Label{}) {
		return Label{One: named.One + ": " + l.One, Many: named.Many + ": " + l.Many, anyLength: l.anyLength}
	}
	return named
}

// Kinds returns the kind of each of labels, as a range of lines names them: a
// value named like a credential is of the kind of what in it looks random, if
// anything does, so a kind found by a name and by its look is named once, and a
// kind found in several lengths is named once, without them.
func Kinds(labels []Label) []Label {
	kinds := make([]Label, len(labels))
	seen, lengths := map[Label]bool{}, map[string]int{}
	for i, l := range labels {
		if one, ok := strings.CutPrefix(l.One, named.One+": "); ok {
			l.One = one
			l.Many, _ = strings.CutPrefix(l.Many, named.Many+": ")
		}
		if l.anyLength != "" && !seen[l] {
			seen[l] = true
			lengths[l.anyLength]++
		}
		kinds[i] = l
	}
	for i, k := range kinds {
		if lengths[k.anyLength] > 1 {
			kinds[i] = Label{One: k.anyLength, Many: k.anyLength}
		}
	}
	return kinds
}

// paddedBase64 matches base64 with its padding, as encoded data is written.
var paddedBase64 = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$`)

// tokenLabel labels what in value looks random, or is zero if nothing does: the
// whole of it as base64 data, or its first random token.
func tokenLabel(value string) Label {
	if len(value) >= minEntropyLen && paddedBase64.MatchString(value) {
		return sized(runOf(fmt.Sprintf("%d characters of base64 data", len(value))), "base64 data")
	}
	label, _ := randomToken(value)
	return label
}

// mixing labels a value random only as a whole, as a password is, by the kinds of
// character in it.
func mixing(value string) Label {
	var letters, digits, symbols bool
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
			letters = true
		case c >= '0' && c <= '9':
			digits = true
		default:
			symbols = true
		}
	}
	var kinds []string
	for _, k := range []struct {
		name string
		in   bool
	}{{"letters", letters}, {"digits", digits}, {"symbols", symbols}} {
		if k.in {
			kinds = append(kinds, k.name)
		}
	}
	return sized(runOf(fmt.Sprintf("%d characters mixing %s", len(value), joinWords(kinds))), "values mixing "+joinWords(kinds))
}

// hexLabel labels the first run of hex digits in s, which may be a UUID.
func hexLabel(s string) Label {
	if uuid.MatchString(strings.Trim(s, "-")) {
		return countable("a UUID")
	}
	for _, r := range runs(s, isHexOrDash) {
		if run := s[r[0]:r[1]]; hexRun(run) {
			return sized(runOf(fmt.Sprintf("%d hex characters", len(strings.ReplaceAll(run, "-", "")))), "runs of hex characters")
		}
	}
	return Label{}
}

// uuid matches a UUID.
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)

// base64Label labels a run of base64: a key where / or + splits it, which an AWS
// secret key's 40 characters may be, and a random token where nothing does.
func base64Label(run string) Label {
	switch n := len(run); {
	case !strings.ContainsAny(run, "/+"):
		return randomLabel(n)
	case n == minSlashedLen:
		return countable("an AWS secret key")
	default:
		return sized(countable(fmt.Sprintf("%s %d-character base64 key", article(n), n)), "base64 keys")
	}
}

// randomLabel labels a random token of n characters.
func randomLabel(n int) Label {
	return sized(countable(fmt.Sprintf("a random %d-character token", n)), "random tokens")
}

// article is the article before n as it is said: an 8, an 11, an 18, an 80.
func article(n int) string {
	if s := strconv.Itoa(n); s[0] == '8' || n == 11 || n == 18 {
		return "an"
	}
	return "a"
}

// joinWords joins words as a list is written: a, b and c.
func joinWords(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// Describe says in plain words what labels name, each once, in the plural where
// it is there more than once, as in "an AWS access key ID and AWS secret keys".
// One that lists words of its own, as "24 characters mixing letters and digits"
// does, comes last, so the and before it is the list's.
func Describe(labels []Label) string {
	var distinct []Label
	count := map[Label]int{}
	for _, l := range labels {
		if count[l]++; count[l] == 1 {
			distinct = append(distinct, l)
		}
	}
	words := make([]string, len(distinct))
	for i, l := range distinct {
		words[i] = l.One
		if count[l] > 1 {
			words[i] = l.Many
		}
	}
	slices.SortStableFunc(words, func(a, b string) int {
		return strings.Count(a, " and ") - strings.Count(b, " and ")
	})
	return joinWords(words)
}
