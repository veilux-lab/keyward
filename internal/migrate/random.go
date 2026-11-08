package migrate

import (
	"slices"
	"strings"
)

// minTokenLen characters mixing upper case, lower case and digits make a random
// token, as do minEntropyLen letters and digits at minEntropyBits.
const minTokenLen = 20

// randomToken labels the first token in s that looks random, if any: minHexLen hex
// digits in a row, base64 of minTokenLen or more that / or + splits and that mixes
// upper case, lower case and digits, minTokenLen token characters mixing all three
// that are no CamelCase identifier, or minEntropyLen letters and digits at
// minEntropyBits. Base64 is read as slashedRuns reads it, so a path is none.
func randomToken(s string) (Label, bool) {
	for _, r := range runs(s, isHexOrDash) {
		if hexRun(s[r[0]:r[1]]) {
			return hexLabel(s[r[0]:r[1]]), true
		}
	}
	for _, r := range slashedRuns(s, minTokenLen) {
		if strings.ContainsAny(s[r[0]:r[1]], "/+") {
			return base64Label(s[r[0]:r[1]]), true
		}
	}
	for _, r := range runs(s, isTokenByte) {
		if t := s[r[0]:r[1]]; len(t) >= minTokenLen && charClasses(t) == 3 && !camelCase(t) {
			return randomLabel(len(t)), true
		}
	}
	for _, r := range runs(s, isAlnum) {
		if t := s[r[0]:r[1]]; len(t) >= minEntropyLen && entropyBits(t) >= minEntropyBits {
			return randomLabel(len(t)), true
		}
	}
	return Label{}, false
}

// holdsRandomToken reports whether s holds a token that looks random, as
// randomToken finds one.
func holdsRandomToken(s string) bool {
	_, ok := randomToken(s)
	return ok
}

// camelCase reports whether s is an identifier made of words, such as
// OAuth2AuthorizedClientManager: letters and digits only, at most two digits and
// none at its end, three quarters of its letters in lowercase runs of three or
// more, and acronyms an identifier is written with, as acronymsKnown finds them.
// A random token rarely is one, and a passphrase's capitalised words, such as I,
// A, OK, TV and USA, are no such acronym.
func camelCase(s string) bool {
	var letters, inWords, run, digits int
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
			letters, run = letters+1, run+1
			continue
		}
		if run >= 3 {
			inWords += run
		}
		run = 0
		switch {
		case i == len(s):
		case isUpper(s[i]):
			letters++
		case s[i] >= '0' && s[i] <= '9':
			digits++
		default:
			return false
		}
	}
	digitLast := len(s) > 0 && s[len(s)-1] >= '0' && s[len(s)-1] <= '9'
	return letters > 0 && digits <= 2 && !digitLast && inWords*4 >= letters*3 && acronymsKnown(s)
}

// acronyms are the acronyms identifiers are written with, as in OAuth2Client,
// HTTPServer and EC2Instance.
var acronyms = []string{"OAuth", "HTTPS", "HTTP", "URL", "URI", "API", "JSON", "XML", "YAML", "SQL", "AWS", "GCP", "IO", "UI", "ID",
	"UUID", "JWT", "TLS", "SSL", "DNS", "IP", "OS", "CPU", "GPU", "DB", "EC2", "IAM", "KMS", "SDK", "CLI", "MCP"}

// acronymsKnown reports whether s, letters and digits, has runs of two or more
// capitals and each is one of acronyms, but for a last capital that starts the
// next word, as the S of Server does in HTTPServer.
func acronymsKnown(s string) bool {
	found := false
	for i := 0; i < len(s); i++ {
		j := i
		for j < len(s) && isUpper(s[j]) {
			j++
		}
		if j-i < 2 {
			continue
		}
		if !slices.ContainsFunc(acronyms, func(a string) bool { return acronymAt(s, i, j, a) }) {
			return false
		}
		found, i = true, j
	}
	return found
}

// acronymAt reports whether acronym a is at i of s, where a run of capitals ends
// at j, and ends a word: no lowercase letter follows it, if it takes in the whole
// run, or one follows the run, if it takes in all of the run but the last capital.
func acronymAt(s string, i, j int, a string) bool {
	if !strings.HasPrefix(s[i:], a) {
		return false
	}
	switch end := i + len(a); {
	case end >= j:
		return end == len(s) || !isLower(s[end])
	case end == j-1:
		return j < len(s) && isLower(s[j])
	}
	return false
}

// slashedRuns returns where text has a run of base64 characters, / included, of
// minLen or more that mixes upper case, lower case and digits, as [start, end).
// Paths and URLs are left out: their runs start with / or follow . or $, or have
// more than maxKeySlashes.
func slashedRuns(text string, minLen int) [][]int {
	var found [][]int
	for _, r := range runs(text, isBase64Byte) {
		run := text[r[0]:r[1]]
		path := run[0] == '/' || r[0] > 0 && strings.IndexByte(".$", text[r[0]-1]) >= 0 ||
			strings.Count(run, "/") > maxKeySlashes
		if len(run) >= minLen && !path && charClasses(run) == 3 {
			found = append(found, r)
		}
	}
	return found
}

// runs returns where s has each longest run of bytes that in is true of, as
// [start, end).
func runs(s string, in func(byte) bool) [][]int {
	var found [][]int
	for i := 0; i < len(s); i++ {
		if !in(s[i]) {
			continue
		}
		start := i
		for i < len(s) && in(s[i]) {
			i++
		}
		found = append(found, []int{start, i})
	}
	return found
}

func isAlnum(c byte) bool {
	return isUpper(c) || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }

func isHexOrDash(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-'
}
