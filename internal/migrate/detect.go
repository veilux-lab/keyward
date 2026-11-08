package migrate

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
)

// Detection is the verdict on one assignment, with the reasoning behind it.
//
// Reason is not decoration. Migration is reviewed by a human before anything is
// written, and a list of variables with no explanation is not reviewable — the
// reader needs to know *why* each line was picked or passed over.
type Detection struct {
	Secret bool

	// Possible marks a value that only looks random. It is never moved: randomness
	// alone also describes compiler flags and hostnames, and no list of safe names
	// can be complete. The user decides instead.
	Possible bool

	// KnownShape marks a secret recognised by the value alone, from a known
	// credential prefix or credentials in a URL, at a credential's length, and in
	// the shape of its kind where its prefix also starts words. A name only
	// suggests one: AUTH is in GIT_AUTHOR_EMAIL.
	KnownShape bool

	Reason string

	// label says what the value looks like, as a value keyward cannot move is
	// described.
	label Label
}

// Thresholds. Deliberately cautious: this is a detector whose findings a human
// approves, so it may suggest generously, but it must not propose moving
// something that would break a shell.
const (
	// minNamedLen is how long a value must be before a suggestive name is enough
	// on its own. Stops TOKEN=x from being treated as a credential.
	minNamedLen = 12

	// minEntropyLen and minEntropyBits flag a random-looking value whose name
	// gives nothing away, as a possible secret rather than a certain one. Base64
	// and hex tokens sit above 4 bits per character; words and versions below.
	minEntropyLen  = 24
	minEntropyBits = 4.0

	// minShapeLen is how long a value with a credential's shape must be to count
	// as one: an AWS key id is 20 characters, while sk-SK and ASIA are words.
	minShapeLen = 20
)

// credentialPrefixes are issuer-specific markers, with the kind of credential
// they mark. A value starting with one of these is a credential regardless of
// what the variable is called.
var credentialPrefixes = []struct {
	kind     string
	prefixes []string
}{
	{"a GitHub token", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}},
	{"a GitLab token", []string{"glpat-"}},
	{"an OpenAI-style API key", []string{"sk-"}},
	{"an Anthropic API key", []string{"sk-ant-"}},
	{"a Slack token", []string{"xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-"}},
	{"an AWS access key ID", []string{"AKIA"}},
	{"a temporary AWS access key ID", []string{"ASIA"}},
	{"a JWT", []string{"eyJ"}}, // base64 of {"
	{"a Google API key", []string{"AIza"}},
	{"a HashiCorp Vault token", []string{"hvs.", "hvb."}},
	{"an npm token", []string{"npm_"}},
	{"a DigitalOcean token", []string{"dop_v1_", "doo_v1_", "dor_v1_"}},
	{"a Shopify token", []string{"shpat_", "shpss_"}},
	{"a Square token", []string{"sq0atp-", "sq0csp-"}},
	{"a Stripe secret key", []string{"sk_live_"}},
	{"a Stripe test key", []string{"sk_test_"}},
	{"a Stripe restricted key", []string{"rk_live_"}},
	{"a SendGrid API key", []string{"SG."}},
	{"a bearer token", []string{"Bearer "}},         // Authorization header
	{"a basic-auth credential", []string{"Basic "}}, // Authorization header
	{"a private key", []string{"-----BEGIN "}},      // PEM block
}

// nameHints are substrings that mark a variable as credential-carrying. Matched
// case-insensitively against the name.
//
// "KEY" is bounded by separators so KEYBOARD_LAYOUT and MONKEY_COUNT do not match.
var nameHints = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
	"APIKEY", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "SIGNING_KEY",
	"SESSION_KEY", "CLIENT_SECRET", "AUTH", "WEBHOOK", "_KEY", "KEY_",
}

// nameWords are password abbreviations, matched only as whole words between
// underscores so BYPASS_PROXY_HOSTS and PASSENGER_LIMIT do not match.
var nameWords = map[string]bool{"PW": true, "PWD": true, "PASS": true, "PASSPHRASE": true}

// safeNames are variables that must never be migrated, whatever they contain.
//
// Several would otherwise be caught by the name heuristic. SSH_AUTH_SOCK is the
// important one: it contains AUTH and its value is a long random-looking path, so
// it looks exactly like a credential — and moving it breaks the ssh agent for
// every shell on the machine.
var safeNames = map[string]bool{
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true, "GPG_TTY": true,
	"PATH": true, "MANPATH": true, "INFOPATH": true, "CDPATH": true,
	"LD_LIBRARY_PATH": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
	"LANG": true, "LANGUAGE": true, "LC_ALL": true, "LC_CTYPE": true, "LC_COLLATE": true,
	"TERM": true, "TERMINFO": true, "COLORTERM": true, "CLICOLOR": true,
	"SHELL": true, "HOME": true, "USER": true, "LOGNAME": true,
	"PWD": true, "OLDPWD": true, "TMPDIR": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true, "LESS": true,
	"MANPAGER": true, "BROWSER": true,
	"PS1": true, "PS2": true, "PROMPT": true, "RPROMPT": true, "PROMPT_COMMAND": true,
	"HISTSIZE": true, "HISTFILE": true, "HISTFILESIZE": true, "SAVEHIST": true,
	"GOPATH": true, "GOROOT": true, "GOBIN": true, "GOPROXY": true, "GOFLAGS": true,
	"JAVA_HOME": true, "ANDROID_HOME": true, "NVM_DIR": true,
	"PYENV_ROOT": true, "RBENV_ROOT": true, "CARGO_HOME": true, "RUSTUP_HOME": true,
	"AWS_PROFILE": true, "AWS_REGION": true, "AWS_DEFAULT_REGION": true,
	"AWS_CONFIG_FILE": true, "AWS_SDK_LOAD_CONFIG": true,
	"DOCKER_HOST": true, "KUBECONFIG": true,
}

// Detect decides whether an assignment holds a secret worth moving.
//
// Exclusions are checked before signals: a value that cannot be a literal secret
// is dismissed before any heuristic has a chance to misfire on it.
func Detect(name, value string) Detection {
	switch {
	case value == "":
		return Detection{Reason: "the value is empty"}

	case handle.IsRef(value):
		return Detection{Reason: "already a keyward reference"}

	// A value the shell expands is not a literal. Whatever the secret is, it is
	// not stored here, so moving this line would break the expansion and protect
	// nothing.
	case hasExpansion(value):
		return Detection{Reason: "the value contains a shell expansion"}

	case safeNames[strings.ToUpper(name)]:
		return Detection{Reason: "a known non-secret variable"}
	}

	// Checked before the path and URL exclusions, because a connection string is
	// both URL-shaped and a credential. This is the only way DATABASE_URL gets
	// caught: nothing in the name suggests a secret.
	if hasURLCredentials(value) {
		return Detection{Secret: true, KnownShape: len(value) >= minShapeLen, Reason: "the value is a URL containing credentials", label: urlLabel}
	}

	switch {
	case looksLikePath(value):
		return Detection{Reason: "the value looks like a path"}
	case looksLikeURL(value):
		return Detection{Reason: "the value is a URL with no credentials in it"}
	}

	// The prefix is part of the value, so the reason names its kind instead.
	if p := matchPrefix(value); p != "" {
		label := prefixLabel(p, value)
		return Detection{Secret: true, KnownShape: knownShape(p, value), Reason: label.One, label: label}
	}

	if hasNameHint(name) {
		if len(value) >= minNamedLen {
			return Detection{Secret: true, Reason: "the variable name suggests a credential", label: namedLabel(value)}
		}
		return Detection{Reason: fmt.Sprintf("the name suggests a credential but the value is under %d characters", minNamedLen)}
	}

	if len(value) >= minEntropyLen && entropyBits(value) >= minEntropyBits {
		if reason := harmless(name, value); reason != "" {
			return Detection{Reason: reason}
		}
		label := tokenLabel(value)
		if label == (Label{}) {
			label = mixing(value)
		}
		return Detection{Possible: true, Reason: label.One, label: label}
	}

	return Detection{Reason: "nothing about the name or value suggests a secret"}
}

// NamesCredential reports whether a variable, or an option, called name suggests
// a credential, as Detect reads a name. Printing hides any value given after such
// an option, whatever its length or what it holds, though doctor does not report it.
func NamesCredential(name string) bool {
	return !safeNames[strings.ToUpper(name)] && hasNameHint(name)
}

// RefName converts a variable name into a reference name: lowercase, with
// underscores as hyphens, which is what makes a migrated file readable.
//
// Returns an error rather than adjusting a name into validity. Silently trimming
// a leading underscore would let _TOKEN and TOKEN collide on one vault entry.
func RefName(varName string) (string, error) {
	candidate := strings.ToLower(strings.ReplaceAll(varName, "_", "-"))
	name, err := handle.Normalize(candidate)
	if err != nil {
		return "", fmt.Errorf("%s cannot become a reference name: %w", varName, err)
	}
	return name, nil
}

// knownShape reports whether value, which starts with the credential prefix p, is
// shaped like the credential p marks. sk-, AKIA and ASIA also start words, as in
// sk-SK and ASIA_PACIFIC, eyJ starts any JSON in base64, and a PEM block may hold
// a public key or a certificate, so each needs its kind's shape: an AWS key id's
// 16 capitals and digits, an OpenAI key's random token, a JWT's three parts, or a
// private key. A JWT is measured by its header, as a token in text is.
func knownShape(p, value string) bool {
	rest := value[len(p):]
	switch p {
	case "AKIA", "ASIA":
		return len(rest) == 16 && strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ""
	case "sk-":
		token := tokenAt(rest)
		return len(p)+len(token) >= minShapeLen && (charClasses(token) == 3 || hexRun(token))
	case "eyJ":
		return len(tokenAt(value)) >= minShapeLen && jwtLen(value) > 0
	case "-----BEGIN ":
		header, _, _ := strings.Cut(rest, "-----")
		return strings.Contains(header, "PRIVATE KEY")
	}
	return len(value) >= minShapeLen
}

// jwtLen returns the length of the JWT s begins with, or 0: a header, payload and
// signature in base64url, joined by dots. A full stop can end a sentence after it.
func jwtLen(s string) int {
	end := 0
	for end < len(s) && (isNameByte(s[end]) || s[end] == '-' || s[end] == '.') {
		end++
	}
	token := strings.TrimSuffix(s[:end], ".")
	if parts := strings.Split(token, "."); len(parts) != 3 || slices.Contains(parts, "") {
		return 0
	}
	return len(token)
}

// CredentialPrefix returns the known credential prefix value starts with, or "".
func CredentialPrefix(value string) string { return matchPrefix(value) }

func matchPrefix(value string) string {
	// Longest match wins, so sk-ant- is reported rather than sk-.
	best := ""
	for _, issuer := range credentialPrefixes {
		for _, p := range issuer.prefixes {
			if strings.HasPrefix(value, p) && len(p) > len(best) {
				best = p
			}
		}
	}
	return best
}

// Thresholds for credentialShaped. What it finds is reported or hidden, never
// moved, so it can afford to be broad.
const (
	// minHexLen hex digits in a row make a key or UUID, as Datadog, Twilio and
	// Heroku issue. A commit hash qualifies too; IgnoreMarker exempts its line.
	minHexLen = 32

	// minSlashedLen is an AWS secret key's length. A / often splits one into
	// pieces shorter than minEntropyLen.
	minSlashedLen = 40

	// A random key that long has more than maxKeySlashes slashes one time in 300.
	// A path that long usually does.
	maxKeySlashes = 3
)

// credentialShaped reports whether text, such as a comment, holds something
// shaped like a credential, as clues finds it, placeholders included.
func credentialShaped(text string) bool { return len(clues(text)) > 0 }

// A clue is text shaped like a credential, at [start, end) of the text it is in.
type clue struct {
	start, end int

	// known marks a credential of a known shape, as Detection.KnownShape does.
	known bool

	// label says what the text looks like.
	label Label

	// placeholder marks text written in place of a credential, which printing
	// hides all the same.
	placeholder bool

	// random marks a token found by its randomness alone, which the comment it is
	// in can show to be none.
	random bool
}

// clues finds what in text, such as a comment, is shaped like a credential: an
// assignment Detect calls a secret or a possible one, a URL with a literal
// password, a known prefix starting a word and followed by a token, or a long
// token. A long token mixes upper case, lower case and digits, is a run of hex
// digits, or is base64 that / splits. Words rarely do any of these, and paths and
// URLs break into short pieces, so ordinary comments stay readable. They are found
// in that order, so what is found twice is labelled as it was found first.
//
// A clue has a known shape as a value does in Detection.KnownShape: a prefix or
// URL credentials at a credential's length, or an assignment Detect gives one. A
// name or randomness alone only suggests one.
func clues(text string) []clue {
	found := assignments(text)
	for _, f := range fieldsAt(text) {
		if field := text[f[0]:f[1]]; hasURLCredentials(field) {
			// Measured from its scheme, as Detect measures the value after NAME=.
			start := strings.Index(field, "://")
			for start > 0 && isTokenByte(field[start-1]) {
				start--
			}
			url := strings.TrimRight(field[start:], `'")]}.,;:!?`)
			found = append(found, clue{start: f[0], end: f[1], known: len(field)-start >= minShapeLen, label: urlLabel, placeholder: Placeholder(url)})
		}
	}
	var tokens []clue
	for i := 0; i < len(text); i++ {
		if i > 0 && isTokenByte(text[i-1]) {
			continue // not where a word starts
		}
		// A prefix is evidence like a credential's name, so it needs as long a
		// value. Two classes after its first letter keep out a capitalised word,
		// as in "Bearer Authentication".
		if p := matchPrefix(text[i:]); p != "" {
			if tail := tokenAt(text[i+len(p):]); len(tail) >= minNamedLen && charClasses(tail[1:]) >= 2 {
				word := p + tail
				if p == "eyJ" {
					// A JWT's parts go on past the dots that end a token.
					word = text[i : i+max(jwtLen(text[i:]), len(word))]
				}
				found = append(found, clue{start: i, end: i + len(word), known: knownShape(p, word), label: prefixLabel(p, word)})
			}
		}
		if n := KeyShaped(text[i:]); n > 0 {
			label := randomLabel(n)
			if word := text[i : i+n]; hexRun(word) {
				label = hexLabel(word)
			}
			tokens = append(tokens, clue{start: i, end: i + n, label: label, random: true})
		}
	}
	for _, r := range slashedRuns(text, minSlashedLen) {
		found = append(found, clue{start: r[0], end: r[1], label: base64Label(text[r[0]:r[1]]), random: true})
	}
	return append(found, tokens...)
}

// KeyShaped returns the length of the token s begins with if it is shaped like a
// random key, or 0: long and mixing upper case, lower case and digits, or holding
// a run of hex digits.
func KeyShaped(s string) int {
	if word := tokenAt(s); len(word) >= minEntropyLen && charClasses(word) == 3 || hexRun(word) {
		return len(word)
	}
	return 0
}

// hexRun reports whether s holds minHexLen hex digits in a row, dashes allowed as
// in a UUID. It needs both letters and digits, which placeholders such as
// 00000000-0000-0000-0000-000000000000 lack.
func hexRun(s string) bool {
	var n, letter, digit int
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			n, digit = n+1, 1
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			n, letter = n+1, 1
		case c != '-':
			n, letter, digit = 0, 0, 0
		}
		if n >= minHexLen && letter+digit == 2 {
			return true
		}
	}
	return false
}

// isBase64Byte reports whether c is in the base64 alphabet, padding aside.
func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// isTokenByte reports whether c can be part of a token: a letter, digit, _, -
// or +. Base64's / and = are left out, since they also join paths and
// assignments.
func isTokenByte(c byte) bool {
	return isNameByte(c) || c == '-' || c == '+'
}

// tokenAt returns the token s begins with, or "".
func tokenAt(s string) string {
	n := 0
	for n < len(s) && isTokenByte(s[n]) {
		n++
	}
	return s[:n]
}

// charClasses counts which of upper case, lower case and digits s contains.
func charClasses(s string) int {
	var upper, lower, digit int
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper = 1
		case c >= 'a' && c <= 'z':
			lower = 1
		case c >= '0' && c <= '9':
			digit = 1
		}
	}
	return upper + lower + digit
}

func hasNameHint(name string) bool {
	upper := strings.ToUpper(name)
	for _, h := range nameHints {
		if strings.Contains(upper, h) {
			return true
		}
	}
	for _, word := range strings.Split(upper, "_") {
		if nameWords[word] {
			return true
		}
	}
	return false
}

func hasExpansion(value string) bool {
	return strings.ContainsAny(value, "$`")
}

func looksLikePath(value string) bool {
	switch {
	case strings.HasPrefix(value, "/"), strings.HasPrefix(value, "~/"),
		strings.HasPrefix(value, "./"), strings.HasPrefix(value, "../"):
		return true
	}
	// A colon-separated list where every entry is a path, as in PATH.
	if strings.Contains(value, ":") && strings.Contains(value, "/") {
		for _, part := range strings.Split(value, ":") {
			if part != "" && !strings.HasPrefix(part, "/") {
				return false
			}
		}
		return true
	}
	return false
}

func looksLikeURL(value string) bool {
	return strings.Contains(value, "://")
}

// hasURLCredentials reports whether value is a URL with a user:password userinfo
// section, as in postgresql://user:pass@host/db, whose password is literal.
func hasURLCredentials(value string) bool {
	i := strings.Index(value, "://")
	if i < 0 {
		return false
	}
	rest := value[i+3:]

	// Userinfo ends at the first @, and must come before any path.
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return false
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 && slash < at {
		return false
	}

	// A colon separating a user from a password is what makes it a credential
	// rather than a bare username. A password the shell expands is stored elsewhere.
	userinfo := rest[:at]
	colon := strings.IndexByte(userinfo, ':')
	return colon > 0 && colon < len(userinfo)-1 && !hasExpansion(userinfo[colon+1:])
}

// entropyBits returns the Shannon entropy of value in bits per character.
//
// A random base64 or hex token lands above 4; words, version numbers, and locale
// strings land below. It is only consulted for values long enough for the figure
// to mean anything.
func entropyBits(value string) float64 {
	var counts [256]int
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}

	n := float64(len(value))
	var bits float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	return bits
}
