package migrate

import (
	"regexp"
	"strings"
)

// Placeholder reports whether value is written in place of a credential: a known
// prefix followed by one character over and over, as in ghp_xxxx, a template in
// angle brackets, as in <your-token>, or a URL whose password is one. Words are
// no placeholder, as a password can be made of them, and printing still hides a
// placeholder.
func Placeholder(value string) bool {
	if p := matchPrefix(value); p != "" {
		if rest := value[len(p):]; rest != "" && strings.Count(rest, rest[:1]) == len(rest) {
			return true
		}
	}
	if m := templateURL.FindStringSubmatch(value); m != nil {
		return template.MatchString(m[1]) && isHost(m[2]) && !holdsRandomToken(value)
	}
	return template.MatchString(value) && !holdsRandomToken(value)
}

// template matches words of letters in angle brackets, joined by spaces, dots,
// underscores or hyphens, as in <your-token> and <API_KEY>.
var template = regexp.MustCompile(`^<[A-Za-z]+(?:[ ._-][A-Za-z]+)*>$`)

// templateURL matches a URL with a user and a password in angle brackets, as in
// postgres://app:<password>@db.internal/app. It captures the password and what
// follows the @, which must be a host name, perhaps with a port and path, and no
// query, which can hold a real key.
var templateURL = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[A-Za-z0-9._-]*:(<[^<>]*>)@(.*)$`)
