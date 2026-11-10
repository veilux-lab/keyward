package shell

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Advice returns the line that shows how to keep f's value out of its
// program's command line, such as by sending it on stdin. Findings that one
// fix covers, as a user and password in one curl command, share the line:
// Advice returns it for the last of them in all and "" for the others, so
// printed after each finding, it follows the ones it fixes.
//
// The line names variables and programs, never what the script holds, which
// could be a credential written into it.
func Advice(f Finding, all []Finding) string {
	return shared(f, all, func(a advice) string { return a.run })
}

// ServerAdvice is Advice for the script of an MCP server, whose stdin carries
// the protocol: its line never sends a value there.
func ServerAdvice(f Finding, all []Finding) string {
	return shared(f, all, func(a advice) string { return a.server })
}

// shared returns the line that of picks from f's advice for the last finding
// of all with the same line, and "" for the others.
func shared(f Finding, all []Finding, of func(advice) string) string {
	for i := len(all) - 1; i >= 0; i-- {
		if of(all[i].advice) == of(f.advice) {
			if all[i] != f {
				return ""
			}
			break
		}
	}
	return of(f.advice)
}

// An advice is the safe form for a use, as keyward run shows it, and for an
// MCP server's script.
type advice struct{ run, server string }

func adviceFor(u use) advice {
	return advice{advise(u, false), advise(u, true)}
}

// A use is the words of one program, in one command, that hold values.
type use struct {
	program string   // as Finding.Program names it
	words   []arg    // the program's name, then its words
	held    []int    // which of words hold a value
	vars    []string // the resolved variables they hold
	then    string   // the program a launcher, such as env, runs
}

// fed returns the words of the program that xargs runs, with what it reads
// where xargs puts it, written as the expansions of vars: in place of marker
// in each word that holds it, for -I or -J, or else after the words; and which
// words hold it.
func fed(words []arg, marker string, vars []string) ([]arg, []int) {
	read := make([]syntax.WordPart, len(vars))
	for i, v := range vars {
		read[i] = &syntax.ParamExp{Short: true, Param: &syntax.Lit{Value: v}}
	}
	if marker == "" {
		return append(slices.Clip(words), arg{word: &syntax.Word{Parts: read}}), []int{len(words)}
	}
	out, held := slices.Clone(words), []int(nil)
	for i, a := range words[1:] {
		if !a.isLit || !strings.Contains(a.lit, marker) {
			continue
		}
		w := &syntax.Word{}
		for j, text := range strings.Split(a.lit, marker) {
			if j > 0 {
				w.Parts = append(w.Parts, read...)
			}
			if text != "" {
				w.Parts = append(w.Parts, &syntax.SglQuoted{Value: text})
			}
		}
		out[i+1], held = arg{word: w}, append(held, i+1)
	}
	return out, held
}

// advise returns the safe form for a use: the program's own way to take the
// value, or else stdin or its environment, or for a server, whose stdin
// carries the protocol, its environment.
func advise(u use, server bool) string {
	v := `"$` + u.vars[0] + `"`
	switch name := u.program; {
	case name == "curl" && server:
		return curlEnvAdvice(u)
	case name == "curl":
		return curlAdvice(u)
	case mysqls[name]:
		return fmt.Sprintf("Pass it in the environment instead: MYSQL_PWD=%s %s ...", u.value(), name)
	case name == "psql" || strings.HasPrefix(name, "pg_"):
		return fmt.Sprintf("Pass it in the environment instead: PGPASSWORD=%s %s ...", u.value(), name)
	case name == "docker":
		if line := dockerAdvice(u, server); line != "" {
			return line
		}
	case name == "git":
		return gitAdvice(u)
	case name == "npx" && remoteAt(u.words) > 0:
		return mcpRemoteAdvice(u)
	case name == "env" && u.then != "":
		for _, i := range u.held {
			if variable, value := assigned(segments(u.words[i].word)); variable != "" {
				return fmt.Sprintf("Set it in front of the command instead, which puts it in the environment only: %s=%s %s ...",
					variable, valueText(value, u.vars), u.then)
			}
		}
	case shells[name]:
		return fmt.Sprintf("Let %s read %s from its environment instead: %s -c '... %s ...'", name, v, name, v)
	case name == "eval":
		return fmt.Sprintf("Write the code in single quotes, so it reads %s only as it runs: eval '... %s ...'", v, v)
	case name == "trap":
		return fmt.Sprintf("Write the command in single quotes, so it reads %s only as it runs: trap '... %s ...' EXIT", v, v)
	case name == "alias":
		return fmt.Sprintf("Write the alias in single quotes, so it reads %s only as it runs: alias NAME='... %s ...'", v, v)
	}
	if server {
		return fmt.Sprintf("Pass it to %s in an environment variable it reads instead.", u.program)
	}
	return fmt.Sprintf("Pass it to %s on stdin or in an environment variable it reads instead.", u.program)
}

// value writes the value of the first word that holds one: the variable it
// expands, if that is all the word is past an option, as in -p"$PW", or else
// the resolved variable, as for a value xargs reads, which no word holds.
func (u use) value() string {
	var value []segment
	if len(u.held) > 0 {
		_, value = split(segments(u.words[u.held[0]].word))
	}
	return valueText(value, u.vars)
}

// curlAdvice writes the words that held values as lines of curl's config,
// which curl -K - reads from stdin, as printf 'user = "%s:%s"\n' "$EMAIL"
// "$TOKEN" | curl -K - gives curl a user and password.
func curlAdvice(u use) string {
	var lines, values []string
	seen := map[string]bool{}
	for _, i := range u.held {
		option, value := u.optionOf(i, curlTakes)
		key := curlKey(option)
		format, args := form(key, value, false)
		line := key + ` = "` + format + `"`
		if k := line + strings.Join(args, " "); !seen[k] {
			seen[k] = true
			lines, values = append(lines, line), append(values, args...)
		}
	}
	if len(lines) == 0 {
		lines, values = []string{`header = "Authorization: Bearer %s"`}, []string{`"$` + u.vars[0] + `"`}
	}
	return fmt.Sprintf(`Send it on stdin instead: printf '%s\n' %s | curl -K - ...`, strings.Join(lines, `\n`), strings.Join(values, " "))
}

// curlEnvAdvice writes the words that held values as options that curl fills
// in from its environment, which holds each value keyward run resolves, as
// curl --variable %T --expand-header 'X-Key: {{T}}' does.
func curlEnvAdvice(u use) string {
	var imported, options []string
	for _, i := range u.held {
		option, value := u.optionOf(i, curlTakes)
		key := curlKey(option)
		text, ok := fill(key, value, u.vars, func(name string) string {
			if !slices.Contains(imported, "--variable %"+name) {
				imported = append(imported, "--variable %"+name)
			}
			return "{{" + name + "}}"
		})
		if !ok {
			return "Pass it to curl in an environment variable instead, which --variable reads."
		}
		if expand := "--expand-" + key + " '" + text + "'"; !slices.Contains(options, expand) {
			options = append(options, expand)
		}
	}
	return fmt.Sprintf("Let curl read %s from its environment instead: curl %s %s ...", pronoun(u.vars), strings.Join(imported, " "), strings.Join(options, " "))
}

// curlTakes reports whether a curl option takes a value.
func curlTakes(option string) bool {
	if long, ok := strings.CutPrefix(option, "--"); ok {
		return curlLong[long]
	}
	return len(option) == 2 && curlShort[option[1]] != ""
}

// curlKey is the name curl's config gives an option that takes a value, or
// "url" for no option.
func curlKey(option string) string {
	if long, ok := strings.CutPrefix(option, "--"); ok {
		return long
	}
	if option == "" {
		return "url"
	}
	return curlShort[option[1]]
}

func dockerAdvice(u use, server bool) string {
	for _, i := range u.held {
		switch option, value := u.optionOf(i, func(o string) bool { return dockerTakes[o] }); option {
		case "-e", "--env":
			variable, value := assigned(value)
			if variable == "" {
				continue
			}
			if len(value) == 1 && value[0].expansion && value[0].text == "$"+variable {
				return fmt.Sprintf("Name the variable alone, so docker reads its value from its own environment: docker ... -e %s ...", variable)
			}
			return fmt.Sprintf("Name the variable alone, and set it for docker, which reads its value from its own environment: %s=%s docker ... -e %s ...",
				variable, valueText(value, u.vars), variable)
		case "-p", "--password":
			if server {
				return "Log docker in once, before the server starts, instead; docker keeps the login."
			}
			return fmt.Sprintf("Send it on stdin instead: printf '%%s' %s | docker login --password-stdin ...", valueText(value, u.vars))
		}
	}
	return ""
}

func gitAdvice(u use) string {
	for _, i := range u.held {
		option, value := u.optionOf(i, func(o string) bool { return o == "-c" })
		key, _, ok := strings.Cut(firstText(value), "=")
		if option != "-c" || !ok || !configKey.MatchString(key) {
			continue
		}
		// http.extraheader holds a header, whose name the safe form can show.
		shape := "config"
		if strings.HasSuffix(strings.ToLower(key), "extraheader") {
			shape = "header"
		}
		text, _ := form(shape, trimText(value, len(key)+1), true)
		return fmt.Sprintf(`Pass it in git's environment instead: GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=%s GIT_CONFIG_VALUE_0="%s" git ...`,
			userinfo.ReplaceAllString(key, "://...@"), text)
	}
	return fmt.Sprintf(`Give it to git through a credential helper instead: git -c credential.helper='!f() { echo username=NAME; echo "password=$%s"; }; f' ...`, u.vars[0])
}

// remoteAt returns where npx's words name mcp-remote, past npx's own options,
// such as -y and -p PACKAGE, or -1 if they do not.
func remoteAt(words []arg) int {
	i, _ := options(lits(words), 1, optionSpec{short: "pc", long: []string{"package", "call"}})
	if i < len(words) && words[i].isLit && (words[i].lit == "mcp-remote" || strings.HasPrefix(words[i].lit, "mcp-remote@")) {
		return i
	}
	return -1
}

// mcpRemoteAdvice writes each header that holds a value with the variable it
// expands as ${VAR}, which mcp-remote fills in from its own environment. It
// fills in nothing of its URL, the word after its name, so a value there can
// go in a header, if the server takes one.
func mcpRemoteAdvice(u use) string {
	var headers, filled, inURL []string
	written := true
	for _, i := range u.held {
		vars := u.varsOf(i)
		option, value := u.optionOf(i, func(o string) bool { return o == "--header" })
		switch {
		case option == "--header":
			filled = append(filled, vars...)
			header, ok := fill("header", value, u.vars, func(name string) string { return "${" + name + "}" })
			headers, written = append(headers, "--header '"+header+"'"), written && ok
		case i == remoteAt(u.words)+1:
			inURL = append(inURL, vars...)
		default:
			filled, written = append(filled, vars...), false
		}
	}
	slices.Sort(filled)
	filled = slices.Compact(filled)
	switch {
	case len(inURL) == 0 && written:
		return fmt.Sprintf("Let mcp-remote fill %s in from its environment instead: npx -y mcp-remote ... %s", pronoun(filled), strings.Join(headers, " "))
	case len(filled) == 0 && len(inURL) == 1:
		return fmt.Sprintf("Send it in a header that mcp-remote fills in from its environment instead, if the server takes one: npx -y mcp-remote ... --header 'Authorization: Bearer ${%s}'", inURL[0])
	}
	line := "Let mcp-remote fill in " + strings.Join(u.vars, ", ") + " from its environment instead, as it does each ${VAR} in a --header"
	if len(inURL) > 0 {
		in, takes := "a header", "one"
		if len(inURL) > 1 {
			in, takes = "headers", "them"
		}
		line += ", with " + strings.Join(inURL, ", ") + " in " + in + ", not its URL, if the server takes " + takes
	}
	if written && len(headers) > 0 {
		return line + ": npx -y mcp-remote ... " + strings.Join(headers, " ")
	}
	return line + "."
}

// varsOf names the resolved variables the word at i holds.
func (u use) varsOf(i int) []string {
	if t := u.words[i].taint; len(t) > 0 {
		return t.names()
	}
	return u.vars // what xargs reads, which no word holds
}

// fill writes a value as form does, with each variable it expands in the
// placeholder of a program that fills it in from its environment, as ${VAR}
// or {{VAR}}. It is false for any other expansion than a resolved variable's,
// which keyward run puts in that environment.
func fill(key string, value []segment, vars []string, placeholder func(name string) string) (string, bool) {
	format, args := form(key, value, false)
	for _, a := range args {
		name := strings.TrimSuffix(strings.TrimPrefix(a, `"$`), `"`)
		if !slices.Contains(vars, name) {
			return "", false
		}
		format = strings.Replace(format, "%s", placeholder(name), 1)
	}
	return format, true
}

// pronoun is it for one variable, and them for more.
func pronoun(vars []string) string {
	if len(vars) > 1 {
		return "them"
	}
	return "it"
}

// optionOf returns the option that the word at i gives its value to: the one
// it starts with, as in -p"$PW", or the word before it, as in -u "$U:$T", if
// takes says that option takes a value; and the value's segments.
func (u use) optionOf(i int, takes func(string) bool) (string, []segment) {
	segs := segments(u.words[i].word)
	if option, value := split(segs); option != "" && takes(option) {
		return option, value
	}
	if i > 1 {
		before := u.words[i-1]
		if before.isLit && len(before.lit) > 1 && before.lit[0] == '-' && before.lit != "--" {
			option := before.lit
			if !strings.HasPrefix(option, "--") {
				option = "-" + option[len(option)-1:] // the last of -sSu takes the value
			}
			if takes(option) {
				return option, segs
			}
		}
	}
	return "", segs
}

// A segment is a run of a word's literal text, or one of its expansions, as
// the safe form writes it: $NAME for a variable, or a placeholder such as
// $(...) for a command substitution.
type segment struct {
	text      string
	expansion bool
}

// segments splits a word into its literal text and its expansions.
func segments(w *syntax.Word) []segment {
	var out []segment
	text := func(s string) {
		if n := len(out); n > 0 && !out[n-1].expansion {
			out[n-1].text += s
		} else if s != "" {
			out = append(out, segment{text: s})
		}
	}
	var add func(parts []syntax.WordPart, escapes string)
	add = func(parts []syntax.WordPart, escapes string) {
		for _, part := range parts {
			switch x := part.(type) {
			case *syntax.Lit:
				text(unescape(x.Value, escapes))
			case *syntax.SglQuoted:
				text(x.Value)
			case *syntax.DblQuoted:
				add(x.Parts, "$`\"\\\n")
			case *syntax.ParamExp:
				out = append(out, segment{text: expansion(x), expansion: true})
			case *syntax.CmdSubst:
				out = append(out, segment{text: "$(...)", expansion: true})
			case *syntax.ArithmExp:
				out = append(out, segment{text: "$((...))", expansion: true})
			default:
				text("...")
			}
		}
	}
	if w != nil {
		add(w.Parts, "")
	}
	return out
}

// expansion writes a parameter expansion: $NAME, or ${NAME...} for one that
// changes the value, whose operands could be literal text.
func expansion(pe *syntax.ParamExp) string {
	if pe.Param == nil {
		return "${...}"
	}
	name := pe.Param.Value
	if pe.Exp != nil || pe.Repl != nil || pe.Slice != nil || pe.Index != nil || pe.Excl || pe.Flags != nil || pe.NestedParam != nil {
		return "${" + name + "...}"
	}
	if len(name) > 1 && name[0] >= '0' && name[0] <= '9' {
		return "${" + name + "}"
	}
	return "$" + name
}

// split separates the option a word starts with, as -p"$PW" and --user=$U:$T
// do, from the value that follows it in the word.
func split(segs []segment) (string, []segment) {
	first := firstText(segs)
	if len(first) < 2 || first[0] != '-' {
		return "", segs
	}
	if long, ok := strings.CutPrefix(first, "--"); ok {
		name, _, inline := strings.Cut(long, "=")
		if !inline {
			return "", segs
		}
		return "--" + name, trimText(segs, len(name)+3)
	}
	return first[:2], trimText(segs, 2)
}

// assigned separates NAME from the value of a word NAME=value.
func assigned(segs []segment) (string, []segment) {
	name, _, ok := strings.Cut(firstText(segs), "=")
	if !ok || !syntax.ValidName(name) {
		return "", nil
	}
	return name, trimText(segs, len(name)+1)
}

func firstText(segs []segment) string {
	if len(segs) == 0 || segs[0].expansion {
		return ""
	}
	return segs[0].text
}

// trimText drops the first n bytes of a word's leading literal text.
func trimText(segs []segment, n int) []segment {
	rest := slices.Clone(segs)
	if rest[0].text = rest[0].text[n:]; rest[0].text == "" {
		rest = rest[1:]
	}
	return rest
}

// valueText writes a value as a shell word: the expansion that is all of it,
// or else the resolved variable it holds.
func valueText(value []segment, vars []string) string {
	if len(value) == 1 && value[0].expansion {
		return `"` + value[0].text + `"`
	}
	return `"$` + vars[0] + `"`
}

// form writes a value for the safe form: a printf format with %s for each
// expansion, and the expansions as printf's arguments, or with inline, the
// text of a double-quoted word. Literal text shows only as much as the key
// lets it without risk of showing a credential: a header's name and
// scheme, as in "Authorization: Bearer ", and the colon of a user. The rest
// is "...", or NAME for a user's name.
func form(key string, value []segment, inline bool) (string, []string) {
	var b strings.Builder
	var args []string
	inUser := key == "user"
	for i, s := range value {
		switch {
		case s.expansion && inline:
			b.WriteString(s.text)
		case s.expansion:
			b.WriteString("%s")
			args = append(args, `"`+s.text+`"`)
		case key == "user":
			for j, part := range strings.Split(s.text, ":") {
				if j > 0 {
					b.WriteString(":")
					inUser = false
				}
				if part != "" && inUser {
					b.WriteString("NAME")
				} else if part != "" {
					b.WriteString("...")
				}
			}
		case key == "header" && i == 0:
			shown := headerOf(s.text)
			b.WriteString(shown)
			if len(shown) < len(s.text) {
				b.WriteString("...")
			}
		default:
			b.WriteString("...")
		}
	}
	return b.String(), args
}

// headerOf returns the start of a header's text that the safe form shows: its
// name, if a message may show it, and a scheme it knows, as in
// "Authorization: Bearer ".
func headerOf(text string) string {
	if m := headerStart.FindStringSubmatch(text); m != nil && shownName(m[1]) {
		return m[0]
	}
	return ""
}

var (
	// headerStart is a header's name, and a scheme in use, such as Bearer; any
	// other word there could be a credential.
	headerStart = regexp.MustCompile(`^([A-Za-z0-9_.-]+): ?(?:(?i:apikey|basic|bearer|bot|digest|dpop|geniekey|key|negotiate|oauth|splunk|ssws|token) )?`)
	// configKey is a git config key, which names a setting, not a value.
	configKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
	// userinfo is the user and password that a URL in a config key can hold,
	// as in http.https://user:password@host/.extraheader.
	userinfo = regexp.MustCompile(`://.*@`)

	mysqls      = setOf("mariadb", "mysql", "mysqladmin", "mysqlcheck", "mysqldump", "mysqlimport", "mysqlpump", "mysqlshow", "mysqlslap")
	dockerTakes = setOf("-e", "--env", "-p", "--password")

	// curlShort maps curl's short options that take a value to their long names,
	// which its config uses.
	curlShort = map[byte]string{'A': "user-agent", 'b': "cookie", 'c': "cookie-jar",
		'C': "continue-at", 'd': "data", 'D': "dump-header", 'e': "referer", 'E': "cert",
		'F': "form", 'H': "header", 'K': "config", 'm': "max-time", 'o': "output",
		'P': "ftp-port", 'Q': "quote", 'r': "range", 't': "telnet-option", 'T': "upload-file",
		'u': "user", 'U': "proxy-user", 'w': "write-out", 'x': "proxy", 'X': "request",
		'y': "speed-time", 'Y': "speed-limit", 'z': "time-cond"}
	// curlLong are curl's long options that take a value.
	curlLong = setOf("aws-sigv4", "cert", "config", "connect-timeout", "cookie", "cookie-jar",
		"data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "form",
		"form-string", "header", "json", "key", "max-time", "oauth2-bearer", "output", "pass",
		"proxy", "proxy-header", "proxy-user", "referer", "request", "retry", "upload-file",
		"url", "user", "user-agent", "variable", "write-out")
)
