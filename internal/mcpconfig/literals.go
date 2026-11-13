package mcpconfig

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/migrate"
)

// Literal is a value in a server definition that looks like a credential. It
// says where the value is, never what it is.
type Literal struct {
	Client, Config, Server string
	// Project is the folder of the Claude Code project a local or project server
	// is in.
	Project string
	// Copilot marks a server Copilot CLI starts, by its own rules: one of its own,
	// or one in a project's .mcp.json once it is installed.
	Copilot bool
	// Field is the key that holds it: env.NAME, headers.NAME, http_headers.NAME,
	// url, or args[N]. In a bridge keyward wrote, it also says which of the remote
	// server's headers, or its URL, the text is, as in "args[6] (its mcp-remote
	// URL)" or "env.KW_HDR_1 (from its X-Api-Key header)".
	Field string
	migrate.Detection
}

// LoadAll is Load plus the servers of every Claude Code project, not just the
// current folder's: its local servers, and those in its folder's .mcp.json,
// .cursor/mcp.json and .github/mcp.json, and in those of each of folders, which no
// tool may list.
// keyward changes a Claude Code project's only from its folder, but a token in
// any of them is plaintext on this Mac all the same.
func LoadAll(home, workdir string, folders ...string) ([]Server, []error) {
	return load(home, workdir, true, folders)
}

// Literals finds credentials written into server definitions, where anything that
// reads the config, an AI agent included, can see them.
func Literals(servers []Server) []Literal {
	var found []Literal
	for _, s := range servers {
		// as names a field as the definition writes it, where that differs.
		var as map[string]string
		// A bridge keyward wrote holds only a remote server's URL and headers, with
		// the headers' text moved into KW_HDR variables, away from the name and
		// scheme that mark a credential. Judge that server, with the text put back,
		// naming the bridge's fields: turned off or unwrapped, it still holds the text.
		if bridge, _, ok := bridgeOf(s); ok {
			script := fmt.Sprintf("args[%d]", len(s.Args)-1)
			s.Env, s.Headers, as = putBack(s.Env, bridge.Headers, script)
			s.URL, s.Args, as["url"] = bridge.URL, nil, script+" (its mcp-remote URL)"
		}
		add := func(field string, d migrate.Detection) {
			if name, ok := as[field]; ok {
				field = name
			}
			if d.Secret || d.Possible {
				found = append(found, Literal{Client: s.Client, Config: s.Config, Server: s.Name, Project: s.Project, Copilot: s.byCopilot(), Field: field, Detection: d})
			}
		}
		// A placeholder holds no credential. An argument is not judged so, as a
		// script can hold one beside a credential.
		for k, v := range s.Env {
			if !migrate.Placeholder(v) {
				add("env."+k, detect(k, v))
			}
		}
		for k, v := range s.Headers {
			if !migrate.Placeholder(v) {
				add("headers."+k, header(k, v))
			}
		}
		for k, v := range s.httpHeaders {
			if !migrate.Placeholder(v) {
				add("http_headers."+k, header(k, v))
			}
		}
		// Read as an argument, so a token after = in the query string counts.
		if !migrate.Placeholder(s.URL) {
			add("url", argument(s.URL))
		}
		for i, a := range s.Args {
			d := argument(a)
			// A header given with --header is judged by its name too, as a bridge's is.
			for _, h := range headersIn(s.Args, i) {
				if name, value, ok := cutHeader(h.String()); ok {
					d = surer(header(name, value), d)
				}
			}
			for _, o := range optionsIn(s.Args, i) {
				d = surer(o.detect(), d)
			}
			add(fmt.Sprintf("args[%d]", i), d)
		}
	}
	slices.SortFunc(found, func(a, b Literal) int {
		return strings.Compare(a.Client+a.Config+a.Server+a.Field, b.Client+b.Config+b.Server+b.Field)
	})
	return found
}

// movedText is a bridge header's ${KW_HDR_n}, named by headerVar, which holds text
// wrap moved out of the header.
var movedText = regexp.MustCompile(`\$\{KW_HDR_[0-9]+\}`)

// putBack puts each KW_HDR variable's text back into the header that reads it,
// and leaves the variable out of env, so the text is judged once. Detect passes
// over a header still holding another placeholder, so its text stays in env, to
// be judged alone. as names the field that holds each header's text, its
// variables or script, and the header each variable's text is from.
func putBack(env, headers map[string]string, script string) (rest, whole, as map[string]string) {
	rest, whole, as = maps.Clone(env), map[string]string{}, map[string]string{}
	for h, v := range headers {
		from := " (from its " + h + " header)"
		var moved []string
		value := movedText.ReplaceAllStringFunc(v, func(p string) string {
			name := p[2 : len(p)-1]
			text, ok := env[name]
			if !ok {
				return p
			}
			moved = append(moved, name)
			as["env."+name] = "env." + name + from
			return text
		})
		switch {
		case placeholder.MatchString(value):
			whole[h] = v
		case len(moved) > 0:
			whole[h], as["headers."+h] = value, "env."+strings.Join(moved, ", env.")+from
			for _, name := range moved {
				delete(rest, name)
			}
		default:
			whole[h], as["headers."+h] = value, script+" (its "+h+" header)"
		}
	}
	return rest, whole, as
}

// header reads a header's name as a variable's, so X-Api-Key matches API_KEY.
func header(name, value string) migrate.Detection {
	return detect(strings.ReplaceAll(name, "-", "_"), value)
}

// detect is migrate.Detect, or, for a value holding a URL, what argument finds in
// it if that is surer: Detect takes a URL without user info to hold no credential,
// but a token can be in its query or path, where one in a server's url is found.
func detect(name, value string) migrate.Detection {
	d := migrate.Detect(name, value)
	if !strings.Contains(value, "://") {
		return d
	}
	return surer(d, argument(value))
}

// surer is whichever of a and b is surer of a credential, a if neither is: one of
// a known shape, then a secret, then one that may be.
func surer(a, b migrate.Detection) migrate.Detection {
	sureness := func(d migrate.Detection) int {
		switch {
		case d.KnownShape:
			return 3
		case d.Secret:
			return 2
		case d.Possible:
			return 1
		}
		return 0
	}
	if sureness(b) > sureness(a) {
		return b
	}
	return a
}

// argument looks for a credential prefix, or credentials in a URL, where a value
// starts in arg: at its beginning, after =, ": " or "Bearer ", at a segment of a
// URL's path, or at a quoted value in JSON, a dict or a list, perhaps behind a
// quote. Anywhere else a prefix is part of a word, as sk- is of task-. A token
// shaped like a key there only may be a credential, with no name to go on.
func argument(arg string) migrate.Detection {
	var found migrate.Detection
	for _, c := range credentials(arg, valueStarts) {
		if c.KnownShape {
			return c.Detection
		}
		if !found.Secret {
			found = c.Detection
		}
	}
	return found
}

// credential is where a credential is in an argument, as [start, end).
type credential struct {
	start, end int
	migrate.Detection
}

// credentials returns each credential in arg that starts at its beginning, at a
// segment of a URL's path, at a quoted value in JSON, a dict or a list, or
// wherever starts says a value does, perhaps behind a quote, which a script
// escapes when wrap quotes JSON or a quoted value again. One in a URL's path ends
// with its segment.
func credentials(arg string, starts func(before string) bool) []credential {
	var found []credential
	segment, quoted := segments(arg), quotedValues(arg)
	for at := range len(arg) {
		if at > 0 && !segment[at] && !quoted[at] && !starts(arg[:at]) {
			continue
		}
		value := strings.TrimLeft(arg[at:], `"'\`)
		ends := wordEnds
		if segment[at] {
			ends += "/?#"
		}
		// Bearer and Basic end in a space, so the word is measured after the prefix.
		skip := len(migrate.CredentialPrefix(value))
		end := strings.IndexAny(value[skip:], ends)
		if end < 0 {
			end = len(value) - skip
		}
		if end == 0 {
			continue
		}
		start := len(arg) - len(value)
		if d := migrate.Detect("", value[:skip+end]); d.Secret {
			found = append(found, credential{start, start + skip + end, d})
		} else if n := migrate.KeyShaped(value); n > 0 {
			found = append(found, credential{start, start + n, migrate.Detection{Possible: true, Reason: "it holds a token shaped like a key"}})
		}
	}
	return found
}

func valueStarts(before string) bool {
	return strings.HasSuffix(before, "=") || strings.HasSuffix(before, ": ") || strings.HasSuffix(before, "Bearer ")
}

// wordEnds are the characters that end a word in an argument, among them the
// backslash that escapes a quote in a script.
const wordEnds = " \t\n\"'\\"

// segments marks each index of arg just after a / in a URL's path, where a segment
// starts that a token can fill, as in https://mcp.example.com/<token>/mcp. It reads
// arg once, as an argument can be long.
func segments(arg string) []bool {
	marked := make([]bool, len(arg))
	// Once a word has a ://, each / after it is in a URL's path.
	inURL := false
	for i := 0; i < len(arg); i++ {
		switch {
		case strings.IndexByte(wordEnds, arg[i]) >= 0:
			inURL = false
		case strings.HasPrefix(arg[i:], "://"):
			inURL = true
			i += len("://") - 1
		case arg[i] == '/' && inURL && i+1 < len(arg):
			marked[i+1] = true
		}
	}
	return marked
}

// quotedValues marks each index of arg where a value starts in JSON, a dict or a
// list: at a quote, perhaps escaped, after a colon, [ or , and any spaces. A word
// that is not quoted, as in host:port, a URL's scheme or a time, starts none. It
// reads arg once, as an argument can be long.
func quotedValues(arg string) []bool {
	marked := make([]bool, len(arg))
	// after is set from a colon, [ or , to the next byte that is not a space.
	after := false
	for i := 0; i < len(arg); i++ {
		switch c := arg[i]; {
		case c == ':' || c == '[' || c == ',':
			after = true
		case after && strings.IndexByte(" \t\n\r", c) < 0:
			quote := i
			for quote < len(arg) && arg[quote] == '\\' {
				quote++
			}
			marked[i] = quote < len(arg) && (arg[quote] == '"' || arg[quote] == '\'')
			after = false
		}
	}
	return marked
}
