package migrate

import (
	"fmt"
	"math"
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

// credentialPrefixes are issuer-specific markers. A value starting with one of
// these is a credential regardless of what the variable is called.
var credentialPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
	"glpat-",         // GitLab
	"sk-", "sk-ant-", // OpenAI, Anthropic
	"xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-", // Slack
	"AKIA", "ASIA", // AWS access key id
	"eyJ",          // JWT: base64 of {"
	"AIza",         // Google
	"hvs.", "hvb.", // HashiCorp Vault
	"npm_",                          // npm
	"dop_v1_", "doo_v1_", "dor_v1_", // DigitalOcean
	"shpat_", "shpss_", // Shopify
	"sq0atp-", "sq0csp-", // Square
	"sk_live_", "sk_test_", "rk_live_", // Stripe
	"SG.",         // SendGrid
	"Bearer ",     // Authorization header
	"Basic ",      // Authorization header
	"-----BEGIN ", // PEM block
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
		return Detection{Secret: true, KnownShape: len(value) >= minShapeLen, Reason: "the value is a URL containing credentials"}
	}

	switch {
	case looksLikePath(value):
		return Detection{Reason: "the value looks like a path"}
	case looksLikeURL(value):
		return Detection{Reason: "the value is a URL with no credentials in it"}
	}

	if p := matchPrefix(value); p != "" {
		return Detection{Secret: true, KnownShape: knownShape(p, value), Reason: fmt.Sprintf("the value begins with %q, a known credential prefix", p)}
	}

	if hasNameHint(name) {
		if len(value) >= minNamedLen {
			return Detection{Secret: true, Reason: "the variable name suggests a credential"}
		}
		return Detection{Reason: fmt.Sprintf("the name suggests a credential but the value is under %d characters", minNamedLen)}
	}

	if len(value) >= minEntropyLen {
		if bits := entropyBits(value); bits >= minEntropyBits {
			return Detection{
				Possible: true,
				Reason:   fmt.Sprintf("%d characters at %.1f bits of entropy per character", len(value), bits),
			}
		}
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
// sk-SK and ASIA_PACIFIC, and a PEM block may hold a public key or a certificate,
// so each needs its kind's shape: an AWS key id's 16 capitals and digits, an
// OpenAI key's random token, or a private key.
func knownShape(p, value string) bool {
	rest := value[len(p):]
	switch p {
	case "AKIA", "ASIA":
		return len(rest) == 16 && strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ""
	case "sk-":
		token := tokenAt(rest)
		return len(p)+len(token) >= minShapeLen && (charClasses(token) == 3 || hexRun(token))
	case "-----BEGIN ":
		header, _, _ := strings.Cut(rest, "-----")
		return strings.Contains(header, "PRIVATE KEY")
	}
	return len(value) >= minShapeLen
}

// CredentialPrefix returns the known credential prefix value starts with, or "".
func CredentialPrefix(value string) string { return matchPrefix(value) }

func matchPrefix(value string) string {
	// Longest match wins, so sk-ant- is reported rather than sk-.
	best := ""
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(value, p) && len(p) > len(best) {
			best = p
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
// shaped like a credential: an assignment Detect calls a secret, a URL with a
// literal password, a known prefix starting a word and followed by a token, or a
// long token. A long token mixes upper case, lower case and digits, is a run of
// hex digits, or is base64 that / splits. Words rarely do any of these, and paths
// and URLs break into short pieces, so ordinary comments stay readable.
//
// known reports whether any of it has a known shape, as Detection.KnownShape does
// for a value: a prefix or URL credentials at a credential's length, or an
// assignment Detect gives one. A name or randomness alone only suggests one.
func credentialShaped(text string) (shaped, known bool) {
	shaped, known = namedSecret(text)
	shaped = shaped || slashedKey(text)
	for _, field := range strings.Fields(text) {
		if hasURLCredentials(field) {
			// Measured from its scheme, as Detect measures the value after NAME=.
			start := strings.Index(field, "://")
			for start > 0 && isTokenByte(field[start-1]) {
				start--
			}
			shaped, known = true, known || len(field)-start >= minShapeLen
		}
	}
	for i := 0; i < len(text); i++ {
		if i > 0 && isTokenByte(text[i-1]) {
			continue // not where a word starts
		}
		// A prefix is evidence like a credential's name, so it needs as long a
		// value. Two classes after its first letter keep out a capitalised word,
		// as in "Bearer Authentication".
		if p := matchPrefix(text[i:]); p != "" {
			if tail := tokenAt(text[i+len(p):]); len(tail) >= minNamedLen && charClasses(tail[1:]) >= 2 {
				shaped, known = true, known || knownShape(p, p+tail)
			}
		}
		if KeyShaped(text[i:]) > 0 {
			shaped = true
		}
	}
	return shaped, known
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

// slashedKey reports whether text holds a run of base64 characters, / included,
// of minSlashedLen or more that mixes upper case, lower case and digits. Paths and
// URLs are left out: their runs start with / or follow . or $, or have more than
// maxKeySlashes.
func slashedKey(text string) bool {
	for i := 0; i < len(text); {
		n := 0
		for i+n < len(text) && isBase64Byte(text[i+n]) {
			n++
		}
		run := text[i : i+n]
		path := strings.HasPrefix(run, "/") || i > 0 && strings.IndexByte(".$", text[i-1]) >= 0 ||
			strings.Count(run, "/") > maxKeySlashes
		if n >= minSlashedLen && !path && charClasses(run) == 3 {
			return true
		}
		i += max(n, 1)
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
