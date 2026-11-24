// Package shell checks the script of a shell that keyward run starts, such as
// sh -c SCRIPT, for a value keyward resolved that the script would put in
// another program's command line.
//
// keyward run hands a command its values in the environment. A script can
// still expand one into a command line, as curl -u "$EMAIL:$TOKEN" does, and
// any process of the user can read a command line, as can security tools such
// as Microsoft Defender, which record it when the program starts. The check
// follows each value through copies, pipes and substitutions into the words of
// every command, and allows what keeps it out of a command line: shell
// builtins such as printf, a program's own environment, and stdin.
//
// It guards against mistakes, not against a script written to get around it.
// It cannot see into a script a shell reads from a file or a pipe, code made
// as the script runs, other languages' code, or programs that put their
// environment into the command line of a program they start. Nor does it
// follow output sent through a descriptor other than stdout and stderr, as
// >&3 sends it, an alias the script defines again, zsh's global aliases, or
// what trap's code writes.
package shell

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Finding is a resolved variable whose value a script would put in a
// program's command line, or run as code, which can put it in one.
type Finding struct {
	// Var is the resolved variable, under its own name even when the script
	// passes on a copy of its value.
	Var string
	// Program is the program whose command line would hold the value, as a
	// message may show it: its base name, $NAME for one a variable names, or
	// "a program" for a name that could be a value pasted in its place. With
	// Code, it is what would run the value as code: eval, trap, alias, or a
	// shell reading its script on stdin.
	Program string
	// Code is set when the value would be part of code the shell runs, rather
	// than of a command line.
	Code bool
	// Line is the script's line that would put it there.
	Line int

	advice advice
}

// Message says where f's value would go, as keyward run says it when it
// refuses the script.
func (f Finding) Message() string {
	if f.Code {
		return fmt.Sprintf("%s would run the value of %s as code (line %d), which can put it in a program's command line.", f.Program, f.Var, f.Line)
	}
	return fmt.Sprintf("%s would get %s in its command line (line %d), where other programs and security logs can read it.", f.Program, f.Var, f.Line)
}

// Check reports where script, run as shell -c script with the resolved
// variables in its environment, would put one of their values in a program's
// command line, or run one as code. shell is sh, bash, dash or zsh, as
// Command returns.
//
// The error says why the script, or one it runs, could not be read, or why
// it could not be followed to its end, and Hint says how to write it so it
// can be. That is an error only if the script names a resolved variable, as
// $NAME or as a word, as in printenv NAME, or if what could not be read names
// a variable that holds a copy of a value, as $NAME or ${NAME; a script that
// names none is left to run unchecked.
func Check(shell, script string, resolved []string) ([]Finding, error) {
	if len(resolved) == 0 {
		return nil, nil // with no value, no command line can get one
	}
	env := map[string]taint{}
	for _, name := range resolved {
		env[name] = taint{name: true}
	}
	c := &checker{index: map[key]int{}, calling: map[*syntax.Stmt][]call{}, timed: map[*syntax.CallExpr]bool{},
		aliasing: map[string]bool{}, late: map[*syntax.Stmt]bool{}, parsed: map[parsing]*syntax.File{},
		resolved: env, mentioned: mentions(script, env)}
	p := c.newProcess(shell, env)
	c.script(p, script, 1, stream{})
	switch {
	case c.steps > maxSteps:
		c.cannotRead(p, script, unreadable{"the script would take too long to check", toSimplify})
	case c.text > maxText:
		c.cannotRead(p, script, unreadable{"the script's variables would hold too much text to check", toSimplify})
	case c.unsettled:
		c.cannotRead(p, script, unreadable{"a loop passes values along too many variables to check", toSimplify})
	case c.recursed:
		c.cannotRead(p, script, unreadable{"a function calls itself too deeply to check", toSimplify})
	}
	if c.err != nil {
		return nil, c.err
	}
	// Two commands on one line that would put a value in the same program's
	// command line, fixed the same way, read as one finding.
	seen := map[Finding]bool{}
	found := slices.DeleteFunc(c.found, func(f Finding) bool {
		again := seen[f]
		seen[f] = true
		return again
	})
	slices.SortStableFunc(found, func(a, b Finding) int { return a.Line - b.Line })
	return found, nil
}

// unreadable says why a script, or one it runs, could not be read or followed
// to its end, and how to write it so that it can be.
type unreadable struct{ why, hint string }

func (u unreadable) Error() string { return u.why }

// Hint returns how to write the script that err, from Check, says could not
// be read or followed to its end, so that Check can.
func Hint(err error) string {
	var u unreadable
	if errors.As(err, &u) {
		return u.hint
	}
	return ""
}

// What to change in a script the check cannot read, by why it cannot.
const (
	toSh       = "Write it in sh syntax for sh -c, which keyward run can read."
	toFix      = "Fix its syntax, so keyward run can read it."
	toSpace    = "keyward run reads $(( and (( as arithmetic: write $( ( and ( ( to start a subshell inside, or fix the arithmetic."
	toSimplify = "Write it more simply, so keyward run can check it."
	toWrite    = "Write that code into the script, or leave it out, so keyward run can read what runs."
	toName     = "Write the command's name into the script, so keyward run can read what it runs."
)

// A taint is the set of resolved variables whose values a string may hold.
type taint map[string]bool

// union returns the values either holds, leaving both unchanged. Most unions
// add nothing, and copy nothing.
func (t taint) union(u taint) taint {
	if len(t) == 0 {
		return u
	}
	for name := range u {
		if !t[name] {
			r := maps.Clone(t)
			maps.Copy(r, u)
			return r
		}
	}
	return t
}

func (t taint) names() []string { return slices.Sorted(maps.Keys(t)) }

// A stream is what a command reads on stdin: what values it may carry and,
// for a here-document or here-string of literal text, the text and the line
// it starts on, which a shell reading its script from stdin would run.
type stream struct {
	taint   taint
	text    string
	line    int
	literal bool
}

// A process is what one shell knows as it runs: what each variable may hold,
// what it exports, and what its script defines. A subshell starts as a copy.
//
// What a variable may hold only grows. Assigning it again keeps the old
// values too, since a branch may not have run the assignment, and a loop
// body runs until a pass adds nothing.
type process struct {
	shell         string // sh, bash, dash or zsh
	vars          map[string]taint
	exported      map[string]bool
	refs          map[string]string // namerefs, as declare -n r=T; "" for any variable
	params        params
	fds           map[int]taint             // descriptors exec opened for reading, as exec 3<<EOF
	funcs         map[string][]*syntax.Stmt // every body each name is given
	codes         map[string][]code         // the texts each variable may hold, nil if the check cannot know one
	aliases       map[string]string
	disabled      map[string]bool // builtins enable -n or disable turned off
	traps         []*syntax.File  // what trap set to run as the shell exits
	outs          [3]sink         // where stdout and stderr may go now, which exec 2>&1 adds to
	allExport     bool            // set -a
	expandAliases bool            // shopt -s expand_aliases
	late          bool            // reading code the shell reads as it runs, as eval's
	steps         *int            // the work of the Check reading it, shared by every process
	text          *int            // the bytes of the texts that variables keep, shared by every process
}

// standard is where a command's stdout and stderr go when nothing redirects
// them: to those of the statement around it.
var standard = [3]sink{1: {stdout: true}, 2: {stderr: true}}

// newProcess returns a shell that starts with env as its environment, whose
// work c counts.
func (c *checker) newProcess(shell string, env map[string]taint) *process {
	p := &process{shell: shell, vars: map[string]taint{}, exported: map[string]bool{},
		refs: map[string]string{}, params: params{known: []taint{nil}}, fds: map[int]taint{},
		funcs: map[string][]*syntax.Stmt{}, codes: map[string][]code{}, aliases: map[string]string{},
		disabled: map[string]bool{}, outs: standard, steps: &c.steps, text: &c.text}
	p.work(len(env))
	for name, t := range env {
		p.vars[name], p.exported[name] = t, true
	}
	return p
}

// work counts the steps of going through n of the things p knows: one, and
// one for each of them.
func (p *process) work(n int) {
	*p.steps += 1 + n
}

// fork returns a copy of p for a subshell, whose changes stay its own. Traps
// are not inherited, and its commands write to the outputs of what starts it,
// such as a substitution.
func (p *process) fork() *process {
	p.work((len(p.vars) + len(p.exported) + len(p.refs) + len(p.fds) + len(p.funcs) + len(p.codes) +
		len(p.aliases) + len(p.disabled) + len(p.params.known)) / knownPerStep)
	q := *p
	q.vars, q.exported, q.refs = maps.Clone(p.vars), maps.Clone(p.exported), maps.Clone(p.refs)
	q.fds, q.funcs, q.aliases, q.disabled = maps.Clone(p.fds), maps.Clone(p.funcs), maps.Clone(p.aliases), maps.Clone(p.disabled)
	q.codes = maps.Clone(p.codes)
	q.params.known = slices.Clone(p.params.known)
	q.traps, q.outs = nil, standard
	return &q
}

// size measures what p knows. It only grows, so a loop pass that leaves it
// the same learned nothing.
func (p *process) size() int {
	p.work((len(p.vars) + len(p.fds) + len(p.codes) + len(p.params.known)) / knownPerStep)
	n := len(p.exported) + len(p.refs) + len(p.aliases) + len(p.disabled) + p.params.size()
	for _, t := range p.vars {
		n += 1 + len(t)
	}
	for _, t := range p.fds {
		n += 1 + len(t)
	}
	for _, codes := range p.codes {
		n += 1 + len(codes)
		if codes == nil {
			n += 1 + maxCodes // more than any texts, so that it grows to none
		}
	}
	for _, s := range p.outs {
		n += s.size()
	}
	if p.allExport {
		n++
	}
	if p.expandAliases {
		n++
	}
	return n
}

// keep records the assignments given with a function or a special builtin,
// which the commands it runs get in their environment, and which outlast it
// in POSIX mode.
func (p *process) keep(env map[string]taint) {
	for name, t := range env {
		p.assign(name, t)
		p.exported[name] = true
	}
}

// assign records that name may now hold t, as well as what it held, as text
// the check cannot know.
func (p *process) assign(name string, t taint) {
	p.assignCode(name, t, nil)
}

func (p *process) get(name string) taint {
	if name == "@" || name == "*" || name == "argv" && p.shell == "zsh" {
		p.work(len(p.params.known))
		return p.params.all()
	}
	// Digits name a positional parameter; the environment can hold any name,
	// such as -1.
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		if n, err := strconv.Atoi(name); err == nil {
			return p.params.at(n)
		}
	}
	t := p.vars[name]
	if target, ok := p.refs[name]; ok {
		if target == "" {
			return p.all()
		}
		t = t.union(p.vars[target])
	}
	return t
}

// all is what any variable may hold, for an expansion whose variable cannot
// be known, such as ${!name}.
func (p *process) all() taint {
	p.work(len(p.vars) + len(p.params.known))
	t := p.params.all().union(p.params.at(0))
	for _, v := range p.vars {
		t = t.union(v)
	}
	return t
}

// environ returns the environment of a program the shell starts: the
// exported variables that may hold a value, and the assignments given with
// the command.
func (p *process) environ(assigned map[string]taint) map[string]taint {
	env := p.exportedVars()
	for name, t := range assigned {
		env[name] = t
	}
	return env
}

// exportedVars returns what each exported variable that may hold a value
// holds: only one the shell assigned a value, or a nameref, can.
func (p *process) exportedVars() map[string]taint {
	p.work(len(p.vars) + len(p.refs))
	env := map[string]taint{}
	add := func(name string) {
		if t := p.get(name); p.exported[name] && len(t) > 0 {
			env[name] = t
		}
	}
	for name := range p.vars {
		add(name)
	}
	for name := range p.refs {
		add(name)
	}
	return env
}

func (p *process) builtin(name string) bool {
	if p.disabled[name] {
		return false
	}
	switch p.shell {
	case "zsh":
		return builtins[name] || zshBuiltins[name]
	case "dash":
		return builtins[name]
	}
	return builtins[name] || bashBuiltins[name]
}

// expands reports whether the shell expands aliases its script defines: sh
// and dash do, bash only after shopt -s expand_aliases, and zsh only in code
// it reads as it runs, such as eval's, as it reads the whole of its -c script
// before running any of it.
func (p *process) expands() bool {
	switch p.shell {
	case "bash":
		return p.expandAliases
	case "zsh":
		return p.late
	}
	return true
}

// reading reads code that p reads as it runs, as eval's, and returns what
// read does.
func (p *process) reading(read func() taint) taint {
	defer func(late bool) { p.late = late }(p.late)
	p.late = true
	return read()
}

// names reports whether text names a variable that holds a value, as $NAME or
// ${NAME, for a script that cannot be read. It reads text once, however many
// variables p knows.
func (p *process) names(text string) bool {
	for _, rest, found := strings.Cut(text, "$"); found; _, rest, found = strings.Cut(rest, "$") {
		rest = strings.TrimPrefix(rest, "{")
		end := 0
		for end < len(rest) && isNameByte(rest[end]) {
			end++
		}
		if len(p.get(rest[:end])) > 0 {
			return true
		}
	}
	return false
}

// mentions reports whether text holds the name of one of vars as a word, as
// $NAME, ${NAME} and printenv NAME do, or holds at all a name that no shell
// expands, such as MY-KEY, which printenv MY-KEY still reads. It reads text
// once for the names a shell expands, however many there are, and once more
// for each other.
func mentions(text string, vars map[string]taint) bool {
	for i := 0; i < len(text); i++ {
		j := i
		for j < len(text) && isNameByte(text[j]) {
			j++
		}
		if _, ok := vars[text[i:j]]; ok && j > i {
			return true
		}
		i = j
	}
	for name := range vars {
		if name != "" && !syntax.ValidName(name) && strings.Contains(text, name) {
			return true
		}
	}
	return false
}

func isNameByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// params are a shell's positional parameters, $0 first. A word that may
// expand to any number of words, as "$@" does, puts what it and the words
// after it hold in every later position: more.
type params struct {
	known []taint
	more  taint
}

// positionals gives the words of a call, or of set --, as $1 on, after $0.
func positionals(zero taint, args []arg) params {
	p := params{known: []taint{zero}}
	for i, a := range args {
		if splits(a.word) {
			for _, rest := range args[i:] {
				p.more = p.more.union(rest.taint)
			}
			break
		}
		p.known = append(p.known, a.taint)
	}
	return p
}

func (p params) at(i int) taint {
	if i < len(p.known) {
		return p.known[i]
	}
	return p.more
}

// all is "$@": every parameter but $0.
func (p params) all() taint {
	t := p.more
	for _, k := range p.known[min(1, len(p.known)):] {
		t = t.union(k)
	}
	return t
}

// merge keeps both, as set -- or shift in a branch may not have run.
func (p params) merge(q params) params {
	r := params{more: p.more.union(q.more)}
	for i := range max(len(p.known), len(q.known)) {
		r.known = append(r.known, p.at(i).union(q.at(i)))
	}
	return r
}

func (p params) shift(n int) params {
	if n < 0 {
		return p // the shell refuses a negative count
	}
	if n >= len(p.known)-1 { // not n+1, which a count of 2^63-1 overflows
		return params{known: p.known[:min(1, len(p.known))], more: p.more}
	}
	return params{known: append([]taint{p.at(0)}, p.known[n+1:]...), more: p.more}
}

// within reports whether each parameter of p holds only what q's does.
func (p params) within(q params) bool {
	for i := range max(len(p.known), len(q.known)) + 1 {
		for name := range p.at(i) {
			if !q.at(i)[name] {
				return false
			}
		}
	}
	return true
}

func (p params) size() int {
	n := len(p.known) + len(p.more)
	for _, t := range p.known {
		n += len(t)
	}
	return n
}

// splits reports whether a word may expand to other than one word: "$@",
// "${a[@]}", an unquoted expansion, or a glob or brace pattern.
func splits(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch x := part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst:
			return true
		case *syntax.Lit:
			if strings.ContainsAny(x.Value, "*?[{") {
				return true
			}
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				if pe, ok := q.(*syntax.ParamExp); ok && (pe.Param != nil && pe.Param.Value == "@" || allIndex(pe.Index)) {
					return true
				}
			}
		}
	}
	return false
}

func allIndex(e syntax.ArithmExpr) bool {
	w, ok := e.(*syntax.Word)
	return ok && (w.Lit() == "@" || w.Lit() == "*")
}

// A key is what makes findings the same: the same variable reaching the same
// program's command line, or code, on the same line, from the same command.
type key struct {
	name, program string
	code          bool
	line          int
	command       syntax.Pos
}

// maxDepth bounds scripts inside scripts, and maxPasses a loop's passes.
// maxScript bounds a script's length, as the parser recurses as deep as a
// script nests, and 300 KB can nest deeper than Go's stack allows. maxProcs
// bounds the >(...) that an output may go to, as exec keeps them for every
// later command; past it, following them would take too long.
// maxSteps bounds the work of a Check, which a short script could make take
// hours, as one whose functions each call the next twice. A step takes about
// as long as reading a statement or a part of a word, going through one of
// the things a shell knows, copying knownPerStep of them, as a subshell does,
// reading bytesPerStep bytes of text, or parsing a byte; parsing a
// parenthesis, which arithmetic can nest deeply, takes parenSteps.
const (
	maxDepth     = 16
	maxPasses    = 8
	maxScript    = 64 << 10
	maxProcs     = 16
	maxSteps     = 1 << 20
	knownPerStep = 8
	bytesPerStep = 32
	parenSteps   = 32
)

// parseSteps is the work of parsing text.
func parseSteps(text string) int {
	return len(text) + parenSteps*strings.Count(text, "(")
}

// checker holds what one Check found.
type checker struct {
	found     []Finding
	index     map[key]int
	err       error
	literals  []string // the script's literal text that has a $, as literalTexts finds it
	depth     int
	stderr    taint                     // what the command being read writes on stderr
	steps     int                       // the work done, which maxSteps bounds
	text      int                       // the bytes of the texts that variables keep, which maxText bounds
	unsettled bool                      // a loop was still learning after maxPasses
	calling   map[*syntax.Stmt][]call   // the calls of each function body being read
	recursed  bool                      // a function called itself too deeply to follow
	timed     map[*syntax.CallExpr]bool // commands dash's time program runs
	aliasing  map[string]bool           // the aliases whose text is replacing a command's name
	late      map[*syntax.Stmt]bool     // the function bodies read as the script ran, as eval defines them
	parsed    map[parsing]*syntax.File  // code read as the script ran, up to maxScript of its text
	cached    int                       // the bytes of the text of the code in parsed
	resolved  map[string]taint          // the variables keyward run resolves
	mentioned bool                      // the script names a resolved variable, as a word
	kept      bool                      // the command read may be exec with only redirections, which last
}

// spend counts n steps of work, and reports whether the check may go on.
func (c *checker) spend(n int) bool {
	c.steps += n
	return c.steps <= maxSteps
}

// cannotRead records why text could not be read, or the script followed to
// its end, which is an error only if the script names a resolved variable, as
// a check that stopped early cannot know where its value went, or text names
// one that holds a value.
func (c *checker) cannotRead(p *process, text string, why unreadable) {
	if c.err == nil && (c.mentioned || p.names(text)) {
		c.err = why
	}
}

// report records the values in t as reaching program's command line from the
// word at, or with code, the code that program runs, in the command whose
// first word is command. Reported again, as in a later loop pass, a finding
// takes the newer advice, which covers every word that pass found.
func (c *checker) report(t taint, program string, code bool, at, command *syntax.Word, fix advice) {
	line := int(at.Pos().Line())
	for _, name := range t.names() {
		k := key{name, program, code, line, command.Pos()}
		if i, ok := c.index[k]; ok {
			c.found[i].advice = fix
			continue
		}
		c.index[k] = len(c.found)
		c.found = append(c.found, Finding{Var: name, Program: program, Code: code, Line: line, advice: fix})
	}
}

// parse reads text that starts on line of the outermost script, padded so its
// positions are that script's.
func (c *checker) parse(p *process, text string, line int) (*syntax.File, bool) {
	padding := max(line-1, 0)
	if !c.spend((padding + len(text)) / bytesPerStep) {
		return nil, false
	}
	if c.depth >= maxDepth {
		c.cannotRead(p, text, unreadable{"scripts are nested too deeply to check", toSimplify})
		return nil, false
	}
	if len(text) > maxScript {
		c.cannotRead(p, text, unreadable{fmt.Sprintf("scripts over %d KB are too long to check", maxScript>>10), toSimplify})
		return nil, false
	}
	if !c.spend(parseSteps(text)) {
		return nil, false
	}
	// Code read again, as eval in a loop reads it, is the same commands, so a
	// >(...) that exec opens there each time is one.
	k := parsing{text, line, p.shell == "zsh", p.late}
	f, ok := c.parsed[k]
	if !ok {
		lang := syntax.LangBash
		if k.zsh {
			lang = syntax.LangZsh
		}
		var err error
		f, err = syntax.NewParser(syntax.Variant(lang)).Parse(strings.NewReader(strings.Repeat("\n", padding)+text), "")
		if err != nil {
			c.cannotRead(p, text, syntaxError(p.shell, err))
			return nil, false
		}
		if c.depth > 1 && c.cached+len(text) <= maxScript {
			c.parsed[k], c.cached = f, c.cached+len(text)
		}
	}
	if c.depth == 1 {
		c.literals = literalTexts(f) // which hold the text of every script inside it
	}
	// Functions are found first, as one may call another defined later. A
	// call may run any body its name is given, before or after it.
	syntax.Walk(f, func(n syntax.Node) bool {
		if fd, ok := n.(*syntax.FuncDecl); ok {
			names := fd.Names
			if fd.Name != nil {
				names = append(names, fd.Name)
			}
			for _, name := range names {
				if !slices.Contains(p.funcs[name.Value], fd.Body) {
					p.funcs[name.Value] = append(slices.Clip(p.funcs[name.Value]), fd.Body)
				}
			}
			if p.late {
				c.late[fd.Body] = true
			}
		}
		return true
	})
	return f, true
}

// A parsing is code the check reads: its text, the line it starts on, and
// how the shell reads it.
type parsing struct {
	text      string
	line      int
	zsh, late bool
}

// script reads text as the whole script of process p, then runs what p's
// traps set to run as it exits, and returns what reaches its stdout.
func (c *checker) script(p *process, text string, line int, in stream) taint {
	out := c.read(p, text, line, in)
	for _, f := range p.traps {
		p.reading(func() taint { return c.stmts(p, f.Stmts, stream{}) })
	}
	return out
}

// read reads text as more of process p's script, as eval does.
func (c *checker) read(p *process, text string, line int, in stream) taint {
	c.depth++
	defer func() { c.depth-- }()
	f, ok := c.parse(p, text, line)
	if !ok {
		return nil
	}
	return c.stmts(p, f.Stmts, in)
}

var (
	// quoted is a segment of a parser message in quotes: backquotes, or Go's
	// double quotes for text that holds a backquote or a control character.
	quoted = regexp.MustCompile("`[^`]*`" + `|"(?:[^"\\]|\\.)*"`)
	// testOperator is a test operator the parser quotes, such as -eq.
	testOperator = regexp.MustCompile(`^-[A-Za-z]{1,2}$`)
	// grammarWords are the words the parser quotes of its own: reserved words,
	// the builtins it reads as syntax, and those of the shapes it names, as in
	// `for foo [in words]`.
	grammarWords = setOf("if", "then", "elif", "else", "fi", "for", "select", "in", "do", "done",
		"while", "until", "case", "esac", "function", "coproc", "let", "time", "declare", "local",
		"export", "readonly", "typeset", "nameref", "foo", "x", "a", "b", "i", "cond", "words",
		"expr", "stmts", "varname")
)

// syntaxError says why the parser could not read a script of shell, leaving
// out any text of the script that it quotes, which could be a credential
// written there, and how to write it so that it can. It shows only what the
// parser quotes of the shell's grammar.
func syntaxError(shell string, err error) unreadable {
	var line uint
	var text string
	hint := toFix
	var pe syntax.ParseError
	var le syntax.LangError
	switch {
	case errors.As(err, &pe):
		line, text = pe.Pos.Line(), pe.Text
		if strings.Contains(text, "arithmetic") || strings.Contains(text, "((") {
			hint = toSpace
		} else if shell == "zsh" {
			hint = toSh // the parser reads only part of zsh's syntax
		}
	case errors.As(err, &le):
		line, text, hint = le.Pos.Line(), strings.SplitN(le.Error(), ": ", 2)[1], toSh
	default:
		return unreadable{err.Error(), hint}
	}
	text = quoted.ReplaceAllStringFunc(text, func(q string) string {
		if grammar(q[1 : len(q)-1]) {
			return q
		}
		return "`...`"
	})
	return unreadable{fmt.Sprintf("line %d: %s", line, text), hint}
}

// grammar reports whether text the parser quotes is the shell's grammar, not
// the script's: an operator, such as ;; or -eq, or grammarWords between
// punctuation, as in ${!foo}.
func grammar(text string) bool {
	if testOperator.MatchString(text) {
		return true
	}
	if strings.ContainsFunc(text, func(r rune) bool { return r < ' ' || r > '~' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' }) {
		return false
	}
	words := strings.FieldsFunc(text, func(r rune) bool { return r < 'a' || r > 'z' })
	if len(words) == 0 {
		return len(text) <= 4 // as long as the longest operator, such as $((
	}
	return !slices.ContainsFunc(words, func(w string) bool { return !grammarWords[w] })
}

// stmts reads statements in turn, and returns what reaches their stdout. Each
// reads the shell's stdin, which exec 0<... may have changed.
func (c *checker) stmts(p *process, list []*syntax.Stmt, in stream) taint {
	var out taint
	for _, st := range list {
		read := in
		read.taint = read.taint.union(p.fds[0])
		out = out.union(c.stmt(p, st, read))
	}
	return out
}

// stmt reads one statement whose stdin is in, and returns what reaches its
// stdout. What reaches its stderr is added to c.stderr, for a statement around
// it that sends stderr to stdout, as 2>&1 does.
func (c *checker) stmt(p *process, st *syntax.Stmt, in stream) taint {
	if st == nil || !c.spend(1) {
		return nil
	}
	r := c.redirect(p, st, in)
	outs := p.outs
	p.outs = standard // the commands it runs write to its own outputs
	stderr, kept := c.stderr, c.kept
	c.stderr, c.kept = nil, false
	wrote := [3]taint{1: c.command(p, st.Cmd, in, r.stdin), 2: c.stderr}
	lasts := c.kept // its command may be exec with only redirections
	c.stderr, c.kept = stderr, kept
	inner := p.outs
	p.outs = outs
	// What an exec inside the command, as in { exec 2>&1; } or a function's,
	// did to an output the statement does not redirect lasts after it.
	for fd := 1; fd <= 2; fd++ {
		if !r.sent[fd] {
			p.outs[fd] = c.through(inner[fd], r.outs)
		}
	}
	if lasts {
		// exec with only redirections keeps the descriptors it opens, and sends
		// stdout and stderr where it says as well as where they went: it may not
		// have run, bash and zsh go on past a file it cannot open, and a later
		// exec >&3 can bring back what exec 3>&1 saved.
		for fd, t := range r.opened {
			p.fds[fd] = p.fds[fd].union(t)
		}
		for fd := 1; fd <= 2; fd++ {
			p.outs[fd] = c.union(p.outs[fd], r.outs[fd])
		}
	}
	var out taint
	fed := map[*syntax.ProcSubst]taint{}
	for fd := 1; fd <= 2; fd++ {
		if r.outs[fd].stdout {
			out = out.union(wrote[fd])
		}
		if r.outs[fd].stderr {
			c.stderr = c.stderr.union(wrote[fd])
		}
		if len(wrote[fd]) > 0 {
			for _, ps := range r.outs[fd].procs {
				fed[ps] = fed[ps].union(wrote[fd])
			}
		}
	}
	// The commands of a >(...) read what the command writes to it, and write
	// to the statement's stdout; so do those of one that exec opened, as in
	// exec > >(cat), for what each later command writes there.
	for _, ps := range r.procs {
		out = out.union(c.stmts(p.fork(), ps.Stmts, stream{taint: fed[ps]}))
	}
	for fd := 1; fd <= 2 && len(fed) > 0; fd++ {
		for _, ps := range r.outs[fd].procs {
			if t := fed[ps]; len(t) > 0 && !slices.Contains(r.procs, ps) {
				delete(fed, ps)
				out = out.union(c.stmts(p.fork(), ps.Stmts, stream{taint: t}))
			}
		}
	}
	return out
}

// redirected is what a statement's redirections give its command: its stdin,
// which counts each descriptor it may read, those it opens for reading, where
// its stdout and stderr go, which outputs it redirects, and the >(...) they
// name.
type redirected struct {
	stdin  stream
	opened map[int]taint
	outs   [3]sink
	sent   [3]bool
	procs  []*syntax.ProcSubst
}

// A sink is where a command's stdout or stderr goes: the statement's own
// stdout or stderr, or neither, as for a file, and the commands of the
// >(...) that read it.
type sink struct {
	stdout, stderr bool
	procs          []*syntax.ProcSubst
}

// through is where s, an output of a command, goes once the statement around
// it sends its own stdout and stderr to outs.
func (c *checker) through(s sink, outs [3]sink) sink {
	t := sink{procs: s.procs}
	for fd, sent := range [3]bool{1: s.stdout, 2: s.stderr} {
		if sent {
			t = c.union(t, outs[fd])
		}
	}
	return t
}

// union is where output goes that is sent both to s and to t. Joining their
// >(...) counts as work, and past maxProcs of them the check gives up.
func (c *checker) union(s, t sink) sink {
	s.stdout, s.stderr = s.stdout || t.stdout, s.stderr || t.stderr
	if len(s.procs) == 0 {
		s.procs = t.procs
		return s
	}
	c.spend(len(t.procs))
	for _, ps := range t.procs {
		if !slices.Contains(s.procs, ps) {
			s.procs = append(slices.Clip(s.procs), ps)
		}
	}
	if len(s.procs) > maxProcs {
		c.spend(maxSteps) // following them all would take too long
	}
	return s
}

// size counts the places s sends output to.
func (s sink) size() int {
	n := len(s.procs)
	for _, sent := range []bool{s.stdout, s.stderr} {
		if sent {
			n++
		}
	}
	return n
}

func (c *checker) redirect(p *process, st *syntax.Stmt, in stream) redirected {
	r := redirected{stdin: in, opened: map[int]taint{}, outs: p.outs}
	send := func(fd int, s sink) {
		if p.shell == "zsh" && r.sent[fd] {
			s = c.union(r.outs[fd], s) // zsh sends an output redirected twice to both places
		}
		r.outs[fd], r.sent[fd] = s, true
	}
	for _, rd := range st.Redirs {
		fd := 0
		if rd.N != nil {
			fd, _ = strconv.Atoi(rd.N.Value)
		} else if rd.Op != syntax.WordHdoc && rd.Op != syntax.Hdoc && rd.Op != syntax.DashHdoc &&
			rd.Op != syntax.RdrIn && rd.Op != syntax.RdrInOut && rd.Op != syntax.DplIn {
			fd = 1
		}
		var src stream
		switch rd.Op {
		case syntax.WordHdoc:
			src = stream{taint: c.word(p, rd.Word, in), line: int(rd.Word.Pos().Line())}
			src.text, src.literal = literal(rd.Word)
		case syntax.Hdoc, syntax.DashHdoc:
			src = c.heredoc(p, rd, in)
		case syntax.RdrIn, syntax.RdrInOut:
			if n, ok := descriptorOf(rd.Word); ok {
				src = r.read(p, n) // /dev/stdin, or /dev/fd/3
			} else {
				src.taint = c.fileInput(p, rd.Word, in, r)
			}
		case syntax.DplIn:
			if n, err := strconv.Atoi(rd.Word.Lit()); err == nil {
				src = r.read(p, n)
			}
		case syntax.DplOut:
			// N>&1 and N>&2 send N where 1 or 2 goes now.
			if fd == 1 || fd == 2 {
				to := sink{}
				if m, err := strconv.Atoi(rd.Word.Lit()); err == nil && (m == 1 || m == 2) {
					to = r.outs[m]
				}
				send(fd, to)
			}
			continue
		case syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
			to := c.output(p, rd.Word, in, &r)
			send(1, to)
			send(2, to)
			continue
		default:
			if to := c.output(p, rd.Word, in, &r); fd == 1 || fd == 2 {
				send(fd, to)
			}
			continue
		}
		r.opened[fd] = r.opened[fd].union(src.taint)
		if fd == 0 {
			r.stdin = src
		} else {
			r.stdin.taint = r.stdin.taint.union(src.taint)
		}
	}
	return r
}

// read is what reading descriptor n gives: stdin, or what the statement or
// exec opened it on.
func (r redirected) read(p *process, n int) stream {
	if n == 0 {
		return r.stdin
	}
	return stream{taint: r.opened[n].union(p.fds[n])}
}

// any is what reading a descriptor the check cannot know gives: stdin, or any
// that the statement or exec opened.
func (r redirected) any(p *process) taint {
	t := r.stdin.taint
	for _, fds := range []map[int]taint{r.opened, p.fds} {
		for _, opened := range fds {
			t = t.union(opened)
		}
	}
	return t
}

// output returns where an output redirection to w sends what is written to
// it: /dev/stdout and /dev/stderr name the statement's own outputs, as they
// point now, as a path the script makes as it runs may, and >(...) the
// commands that read it.
func (c *checker) output(p *process, w *syntax.Word, in stream, r *redirected) sink {
	if n, ok := descriptorOf(w); ok && (n == 1 || n == 2) {
		return r.outs[n]
	}
	if len(w.Parts) == 1 {
		if ps, ok := w.Parts[0].(*syntax.ProcSubst); ok && ps.Op == syntax.CmdOut {
			r.procs = append(r.procs, ps)
			return sink{procs: []*syntax.ProcSubst{ps}}
		}
	}
	c.word(p, w, in)
	if _, ok := literal(w); !ok && mayName(segments(w), "/dev/stdout", "/dev/stderr") {
		return c.through(sink{stdout: true, stderr: true}, r.outs)
	}
	return sink{}
}

// descriptorOf returns the descriptor that a path such as /dev/stdin or
// /dev/fd/3 opens.
func descriptorOf(w *syntax.Word) (int, bool) {
	path, ok := literal(w)
	if !ok {
		return 0, false
	}
	return descriptor(path)
}

func descriptor(path string) (int, bool) {
	switch path {
	case "/dev/stdin":
		return 0, true
	case "/dev/stdout":
		return 1, true
	case "/dev/stderr":
		return 2, true
	}
	if n, ok := strings.CutPrefix(path, "/dev/fd/"); ok {
		fd, err := strconv.Atoi(n)
		return fd, err == nil && fd >= 0
	}
	return 0, false
}

// heredoc is what a here-document gives a command to read. Under a quoted
// delimiter, as <<'EOF', its text is as written; otherwise a backslash
// escapes $, `, \ and a newline.
func (c *checker) heredoc(p *process, r *syntax.Redirect, in stream) stream {
	if r.Hdoc == nil {
		return stream{literal: true}
	}
	s := stream{taint: c.word(p, r.Hdoc, in), line: int(r.Hdoc.Pos().Line())}
	s.text, s.literal = hereText(r)
	return s
}

// hereText returns the text of a here-document that expands nothing.
func hereText(r *syntax.Redirect) (string, bool) {
	if r.Hdoc == nil {
		return "", true
	}
	lit, ok := r.Hdoc.Parts[0].(*syntax.Lit)
	switch {
	case !ok || len(r.Hdoc.Parts) != 1:
		return "", false
	case plain(r.Word):
		return unescape(lit.Value, "$`\\\n"), true
	}
	return lit.Value, true
}

// fileInput is what < WORD reads, before r redirects it: the output of the
// command in < <(command), any descriptor for a path the script makes as it
// runs, as "$p" may be /dev/stdin, and otherwise a file, which holds no value
// the check can follow.
func (c *checker) fileInput(p *process, w *syntax.Word, in stream, r redirected) taint {
	if len(w.Parts) == 1 {
		if ps, ok := w.Parts[0].(*syntax.ProcSubst); ok && ps.Op == syntax.CmdIn {
			return c.stmts(p.fork(), ps.Stmts, in)
		}
	}
	c.word(p, w, in)
	if _, ok := literal(w); !ok && mayRead(segments(w)) {
		return r.any(p)
	}
	return nil
}

// command reads a command. Its words expand reading in, the stdin of the
// statement, while it runs reading stdin, after the statement's redirections:
// a shell expands a command's words before it redirects them.
func (c *checker) command(p *process, cmd syntax.Command, in, stdin stream) taint {
	switch x := cmd.(type) {
	case *syntax.CallExpr:
		return c.call(p, x, in, stdin)
	case *syntax.DeclClause:
		return c.declClause(p, x, in)
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			stderr := c.stderr
			c.stderr = nil
			piped := c.stmt(p, x.X, stdin)
			if x.Op == syntax.PipeAll {
				piped = piped.union(c.stderr) // |& pipes stderr too
			} else {
				stderr = stderr.union(c.stderr)
			}
			c.stderr = stderr
			return c.stmt(p, x.Y, stream{taint: piped})
		}
		return c.stmt(p, x.X, stdin).union(c.stmt(p, x.Y, stdin))
	case *syntax.Block:
		return c.stmts(p, x.Stmts, stdin)
	case *syntax.Subshell:
		return c.stmts(p.fork(), x.Stmts, stdin)
	case *syntax.IfClause:
		var out taint
		for ; x != nil; x = x.Else {
			out = out.union(c.stmts(p, x.Cond, stdin)).union(c.stmts(p, x.Then, stdin))
		}
		return out
	case *syntax.WhileClause:
		return c.repeat(p, func() taint { return c.stmts(p, x.Cond, stdin).union(c.stmts(p, x.Do, stdin)) })
	case *syntax.ForClause:
		switch l := x.Loop.(type) {
		case *syntax.WordIter:
			items := p.get("@") // for v; do ... reads "$@"
			if l.InPos.IsValid() {
				items = nil
				for _, w := range l.Items {
					items = items.union(c.word(p, w, stdin))
				}
			}
			p.assign(l.Name.Value, items)
		case *syntax.CStyleLoop:
			c.arithm(p, l.Init, stdin)
			c.arithm(p, l.Cond, stdin)
			c.arithm(p, l.Post, stdin)
		}
		return c.repeat(p, func() taint { return c.stmts(p, x.Do, stdin) })
	case *syntax.CaseClause:
		c.word(p, x.Word, stdin)
		var out taint
		for _, item := range x.Items {
			for _, pattern := range item.Patterns {
				c.word(p, pattern, stdin)
			}
			out = out.union(c.stmts(p, item.Stmts, stdin))
		}
		return out
	case *syntax.TestClause:
		c.test(p, x.X, in)
	case *syntax.ArithmCmd:
		c.arithm(p, x.X, in)
	case *syntax.LetClause:
		for _, e := range x.Exprs {
			c.arithm(p, e, in)
		}
	case *syntax.TimeClause:
		// dash has no time keyword, so /usr/bin/time runs the command after it,
		// even a builtin's name.
		if first := leftmost(x.Stmt); p.shell == "dash" && first != nil {
			c.timed[first] = true
		}
		return c.stmt(p, x.Stmt, stdin)
	case *syntax.CoprocClause:
		c.stmt(p.fork(), x.Stmt, stdin)
	case *syntax.FuncDecl:
		if x.Name == nil && len(x.Names) == 0 {
			return c.stmt(p, x.Body, stdin) // zsh's anonymous function runs at once
		}
	}
	return nil
}

// test reads an expression of [[ ]]. The string that =~ matches is copied
// into BASH_REMATCH, and into zsh's MATCH and match.
func (c *checker) test(p *process, e syntax.TestExpr, in stream) {
	switch x := e.(type) {
	case *syntax.Word:
		c.word(p, x, in)
	case *syntax.BinaryTest:
		w, matched := x.X.(*syntax.Word)
		if !matched || x.Op != syntax.TsReMatch {
			c.test(p, x.X, in)
			c.test(p, x.Y, in)
			return
		}
		t := c.word(p, w, in)
		c.test(p, x.Y, in)
		for _, name := range rematch[p.shell] {
			p.assign(name, t)
		}
	case *syntax.UnaryTest:
		c.test(p, x.X, in)
	case *syntax.ParenTest:
		c.test(p, x.X, in)
	}
}

// rematch are the variables that =~ copies what it matches into, by shell.
var rematch = map[string][]string{"sh": {"BASH_REMATCH"}, "bash": {"BASH_REMATCH"}, "zsh": {"MATCH", "match", "BASH_REMATCH"}}

// leftmost returns the first command of a pipeline, if it is simple.
func leftmost(st *syntax.Stmt) *syntax.CallExpr {
	for st != nil {
		switch x := st.Cmd.(type) {
		case *syntax.BinaryCmd:
			if x.Op != syntax.Pipe && x.Op != syntax.PipeAll {
				return nil
			}
			st = x.X
		case *syntax.CallExpr:
			return x
		default:
			return nil
		}
	}
	return nil
}

// repeat reads a loop body until a pass learns nothing new, so that a pass
// sees what the one before assigned. A body still learning after maxPasses
// leaves the loop unsettled, as another pass could have found more.
func (c *checker) repeat(p *process, pass func() taint) taint {
	var out taint
	for range maxPasses {
		before := p.size()
		out = out.union(pass())
		if p.size() == before {
			return out
		}
	}
	c.unsettled = true
	return out
}

// An arg is one word of a simple command: what it may hold once expanded and,
// if it has no expansions, its text after quote removal.
type arg struct {
	word  *syntax.Word
	taint taint
	lit   string
	isLit bool
}

func (c *checker) arg(p *process, w *syntax.Word, in stream) arg {
	lit, ok := literal(w)
	return arg{word: w, taint: c.word(p, w, in), lit: lit, isLit: ok}
}

func joined(args []arg) taint {
	var t taint
	for _, a := range args {
		t = t.union(a.taint)
	}
	return t
}

func lits(args []arg) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a.lit
	}
	return out
}

func (c *checker) call(p *process, ce *syntax.CallExpr, in, stdin stream) taint {
	// VAR=value COMMAND puts the value in the command's environment, not in its
	// command line; alone, it assigns.
	env := map[string]taint{}
	for _, a := range ce.Assigns {
		t := c.assignValue(p, a, in)
		if len(ce.Args) == 0 {
			p.assignCode(a.Name.Value, t, c.literalCode(p, a))
		} else {
			env[a.Name.Value] = env[a.Name.Value].union(t)
		}
	}
	if len(ce.Args) == 0 {
		return nil
	}
	args := make([]arg, len(ce.Args))
	for i, w := range ce.Args {
		args[i] = c.arg(p, w, in)
	}
	if last := args[len(args)-1].taint; len(last) > 0 && p.shell != "dash" {
		p.vars["_"] = p.vars["_"].union(last) // $_ is the last word of the command before
	}
	if c.timed[ce] {
		return c.program(p, append([]arg{{word: ce.Args[0], lit: "time", isLit: true}}, args...), env, stdin)
	}
	return c.run(p, args, env, stdin)
}

func (c *checker) assignValue(p *process, a *syntax.Assign, in stream) taint {
	c.arithm(p, a.Index, in)
	t := c.word(p, a.Value, in)
	if a.Array != nil {
		for _, e := range a.Array.Elems {
			c.arithm(p, e.Index, in)
			t = t.union(c.word(p, e.Value, in))
		}
	}
	return t
}

// run reads a simple command once its words are expanded: an alias, a
// function the script defines, a builtin, or else a program.
func (c *checker) run(p *process, args []arg, env map[string]taint, in stream) taint {
	if c.isAlias(p, args[0]) {
		return c.alias(p, args, env, in)
	}
	return c.dispatch(p, args, env, in)
}

// isAlias reports whether the shell replaces a command's word with an alias's
// text: it names one, where the shell expands aliases, without quotes, and not
// one whose text is replacing a name already.
func (c *checker) isAlias(p *process, a arg) bool {
	_, ok := p.aliases[a.lit]
	return ok && a.isLit && p.expands() && plain(a.word) && !c.aliasing[a.lit]
}

// alias reads a command whose name is an alias, which the shell replaces with
// the alias's text, read as script. A text that ends in a blank makes the
// next word an alias too, as alias run='nohup ' does. The text's last command
// takes the command's other words, and its name can be another alias, but not
// one being replaced already.
func (c *checker) alias(p *process, args []arg, env map[string]taint, in stream) taint {
	text := p.aliases[args[0].lit]
	c.aliasing[args[0].lit] = true
	defer delete(c.aliasing, args[0].lit)
	for len(args) > 1 && strings.TrimRight(text, " \t") != text && c.isAlias(p, args[1]) {
		name := args[1].lit
		text += p.aliases[name]
		c.aliasing[name] = true
		defer delete(c.aliasing, name)
		args = append(args[:1:1], args[2:]...)
	}
	c.depth++
	defer func() { c.depth-- }()
	f, ok := c.parse(p, text, int(args[0].word.Pos().Line()))
	if !ok {
		return nil
	}
	if len(f.Stmts) == 0 {
		if len(args) > 1 {
			return c.dispatch(p, args[1:], env, in) // an alias of no text, as alias x=''
		}
		return nil
	}
	last := f.Stmts[len(f.Stmts)-1]
	ce, simple := last.Cmd.(*syntax.CallExpr)
	if !simple || len(ce.Args) == 0 || len(last.Redirs) > 0 || last.Background || last.Negated {
		// The words go to a command the check does not take apart, as the
		// alias's name, in a command line of their own.
		out := c.stmts(p, f.Stmts, in)
		if len(args) > 1 {
			out = out.union(c.program(p, args, env, in))
		}
		return out
	}
	out := c.stmts(p, f.Stmts[:len(f.Stmts)-1], in)
	words := make([]arg, 0, len(ce.Args)+len(args)-1)
	for _, w := range ce.Args {
		words = append(words, c.arg(p, w, in))
	}
	for _, a := range ce.Assigns {
		env[a.Name.Value] = env[a.Name.Value].union(c.assignValue(p, a, in))
	}
	return out.union(c.run(p, append(words, args[1:]...), env, in))
}

// dispatch reads a simple command whose name is no alias.
func (c *checker) dispatch(p *process, args []arg, env map[string]taint, in stream) taint {
	if !args[0].isLit {
		// A name made as the script runs is a program, a builtin, or any
		// function whose name it could be.
		out := c.made(p, args, env, in)
		prefix, suffix := ends(segments(args[0].word))
		p.work(len(p.funcs))
		for _, name := range slices.Sorted(maps.Keys(p.funcs)) {
			if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
				out = out.union(c.functions(p, name, args[1:], env, in))
			}
		}
		return out
	}
	name := args[0].lit
	switch {
	case strings.Contains(name, "/") || p.shell == "zsh" && strings.HasPrefix(name, "="):
		return c.program(p, args, env, in) // a path, or zsh's =name, is the program
	case p.funcs[name] != nil:
		return c.functions(p, name, args[1:], env, in)
	}
	return c.named(p, name, args, env, in)
}

// made reads a command whose name is made as the script runs, as a program
// or a builtin: exec, whose redirections then last, or eval, which runs its
// words as code the check does not read, as a shell given -c would.
func (c *checker) made(p *process, args []arg, env map[string]taint, in stream) taint {
	c.kept = true
	words := args[1:]
	if splits(args[0].word) {
		words = args // the name may split into eval and its code
	}
	if len(words) > 0 && len(joined(words)) == 0 {
		texts := c.literals // what code the check cannot know could be
		if codes, ok := c.codesOf(p, words); ok {
			texts = nil
			for _, code := range codes {
				texts = append(texts, code.text)
			}
		}
		c.mayRun(p, texts, unreadable{fmt.Sprintf("line %d: a command named as the script runs may run its words as code", args[0].word.Pos().Line()), toName})
	}
	return c.program(p, args, env, in)
}

// ends returns the literal text a word starts and ends with, around its
// expansions, as get_ in "get_$e".
func ends(segs []segment) (string, string) {
	prefix, suffix := firstText(segs), ""
	if n := len(segs); n > 1 && !segs[n-1].expansion {
		suffix = segs[n-1].text
	}
	return prefix, suffix
}

// plain reports whether a word is one literal without quotes or backslashes.
func plain(w *syntax.Word) bool {
	if w == nil || len(w.Parts) != 1 {
		return false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	return ok && !strings.Contains(lit.Value, `\`)
}

// functions reads a call of a function, which runs any body its name is given.
func (c *checker) functions(p *process, name string, args []arg, env map[string]taint, in stream) taint {
	var out taint
	for _, body := range p.funcs[name] {
		out = out.union(c.function(p, body, args, env, in))
	}
	return out
}

// A call is a call of a function whose body is being read: its parameters,
// and how much the shell knew besides them as it began, by p.size.
type call struct {
	params params
	known  int
}

// function reads a call of a function, whose body runs in the same shell with
// the call's words as its positional parameters. A call inside the body it
// runs is read only if it could learn more than the call around it: if its
// parameters hold more, or the shell has learned more since that call began.
func (c *checker) function(p *process, body *syntax.Stmt, args []arg, env map[string]taint, in stream) taint {
	p.keep(env)
	this := call{params: positionals(p.params.at(0), args), known: p.size() - p.params.size()}
	calls := c.calling[body]
	p.work(len(calls) * len(this.params.known))
	if slices.ContainsFunc(calls, func(outer call) bool { return outer.known == this.known && this.params.within(outer.params) }) {
		return nil
	}
	if len(calls) >= maxDepth {
		c.recursed = true
		return nil
	}
	c.calling[body] = append(calls, this)
	defer func() { c.calling[body] = calls }()
	saved := p.params
	p.params = this.params
	defer func() { p.params = saved }()
	defer func(late bool) { p.late = late }(p.late)
	p.late = c.late[body] // zsh expanded its aliases as it read the body
	return c.stmt(p, body, in)
}

// named reads a command that names no function: a builtin of this shell, or
// else a program found in PATH.
func (c *checker) named(p *process, name string, args []arg, env map[string]taint, in stream) taint {
	if !p.builtin(name) {
		return c.program(p, args, env, in)
	}
	if special[name] {
		p.keep(env)
	}
	rest := args[1:]
	switch name {
	case "command":
		return c.commandBuiltin(p, rest, env, in)
	case "builtin":
		switch {
		case len(rest) > 0 && !rest[0].isLit:
			return c.made(p, rest, env, in) // as exec or command, it may run a program
		case len(rest) > 0 && p.builtin(rest[0].lit):
			return c.named(p, rest[0].lit, rest, env, in)
		}
		return nil
	case "exec":
		return c.exec(p, rest, env, in)
	case "eval":
		return c.eval(p, rest, in)
	case "trap":
		c.trap(p, rest)
		return nil
	case "noglob", "nocorrect":
		if len(rest) > 0 {
			return c.run(p, rest, env, in)
		}
		return nil
	}
	return c.builtin(p, name, args, in)
}

// commandBuiltin reads command NAME, which skips functions. It runs a builtin
// in sh, bash and dash, but in zsh the program of that name.
func (c *checker) commandBuiltin(p *process, rest []arg, env map[string]taint, in stream) taint {
	for len(rest) > 0 && isOption(rest[0]) {
		option := rest[0].lit
		rest = rest[1:]
		if option == "--" {
			break
		}
		if strings.ContainsAny(option, "vV") {
			return nil // command -v only looks a name up
		}
	}
	switch {
	case len(rest) == 0:
		return nil
	case p.shell == "zsh" || strings.Contains(rest[0].lit, "/"):
		return c.program(p, rest, env, in)
	case !rest[0].isLit:
		return c.made(p, rest, env, in)
	}
	return c.named(p, rest[0].lit, rest, env, in)
}

func isOption(a arg) bool {
	return a.isLit && len(a.lit) > 1 && a.lit[0] == '-'
}

// exec reads exec COMMAND. It replaces the shell with the program even of a
// builtin's name in sh, bash and dash, but zsh runs a builtin. The name that
// -a gives becomes the program's first word in place of its own name, so
// what the name holds is held by that word.
func (c *checker) exec(p *process, rest []arg, env map[string]taint, in stream) taint {
	var argv0 taint
	for len(rest) > 0 && isOption(rest[0]) {
		option := rest[0].lit
		rest = rest[1:]
		if option == "--" {
			break
		}
		if strings.HasSuffix(option, "a") && len(rest) > 0 {
			argv0, rest = rest[0].taint, rest[1:]
		}
	}
	// With no words, or words that may expand to none, as $NONE does, exec has
	// only redirections, which stmt keeps.
	if !slices.ContainsFunc(rest, func(a arg) bool { return !splits(a.word) }) {
		c.kept = true
	}
	if len(rest) == 0 {
		return nil
	}
	if len(argv0) > 0 {
		name := rest[0]
		name.taint = name.taint.union(argv0)
		rest = append([]arg{name}, rest[1:]...)
	}
	if p.shell == "zsh" {
		return c.run(p, rest, env, in)
	}
	return c.program(p, rest, env, in)
}

// eval reads its words, joined, as more of the script. A value among them
// would be part of the code.
func (c *checker) eval(p *process, rest []arg, in stream) taint {
	if t := joined(rest); len(t) > 0 {
		for _, a := range rest {
			if len(a.taint) > 0 {
				c.report(a.taint, "eval", true, a.word, rest[0].word, adviceFor(use{program: "eval", vars: t.names()}))
			}
		}
		return nil
	}
	if len(rest) == 0 {
		return nil
	}
	codes, ok := c.codesOf(p, rest)
	if !ok {
		c.unknownCode(p, "eval", rest[0].word)
		return nil
	}
	var out taint
	for _, code := range codes {
		out = out.union(p.reading(func() taint { return c.read(p, code.text, code.line, in) }))
	}
	return out
}

// trap reads the command that trap sets, which the shell runs later as more
// of its script: where it is set, and as the shell exits.
func (c *checker) trap(p *process, rest []arg) {
	for len(rest) > 0 && isOption(rest[0]) {
		if rest[0].lit != "--" {
			return // trap -p and -l print
		}
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return
	}
	action := rest[0]
	if len(action.taint) > 0 {
		c.report(action.taint, "trap", true, action.word, action.word, adviceFor(use{program: "trap", vars: action.taint.names()}))
		return
	}
	if _, err := strconv.Atoi(action.lit); action.isLit && (action.lit == "" || action.lit == "-" || err == nil) {
		return // one that resets or ignores
	}
	codes, ok := c.codesOf(p, rest[:1])
	if !ok {
		c.unknownCode(p, "trap", action.word)
		return
	}
	c.depth++
	defer func() { c.depth-- }()
	for _, code := range codes {
		p.reading(func() taint {
			if f, ok := c.parse(p, code.text, code.line); ok {
				c.stmts(p.fork(), f.Stmts, stream{})
				p.traps = append(p.traps, f)
			}
			return nil
		})
	}
}

// builtin reads a builtin, whose words reach no program's command line:
// what it prints, and what it copies into variables.
func (c *checker) builtin(p *process, name string, args []arg, in stream) taint {
	rest := args[1:]
	switch name {
	case "echo", "print", "printf":
		if len(rest) > 1 && rest[0].lit == "-v" && name != "echo" {
			p.assign(rest[1].lit, joined(rest[2:])) // printf -v NAME assigns what it would print
			return nil
		}
		return joined(rest)
	case "read":
		names, values := operands(rest, readOptions[p.shell])
		t := in.taint
		if fd, err := strconv.Atoi(values['u']); err == nil {
			t = t.union(p.fds[fd])
		}
		if array, ok := values['a']; ok {
			names = append(names, array) // bash's read -a NAME
		}
		switch {
		case len(names) > 0:
		case p.shell == "zsh" && slices.ContainsFunc(rest, func(a arg) bool { return isOption(a) && strings.Contains(a.lit, "A") }):
			names = []string{"reply"} // zsh's read -A
		default:
			names = []string{"REPLY"}
		}
		for _, n := range names {
			if n != "" {
				p.assign(strings.SplitN(n, "?", 2)[0], t) // zsh's read NAME?PROMPT
			}
		}
	case "mapfile", "readarray":
		names, values := operands(rest, "CcdnOsu")
		t := in.taint
		if fd, err := strconv.Atoi(values['u']); err == nil {
			t = t.union(p.fds[fd])
		}
		if len(names) == 0 {
			names = []string{"MAPFILE"}
		}
		p.assign(names[0], t)
	case "getopts":
		// getopts copies the argument of an option it reads into OPTARG.
		if len(rest) > 2 {
			p.assign("OPTARG", joined(rest[2:]))
		} else {
			p.assign("OPTARG", p.get("@"))
		}
	case "set":
		return c.set(p, rest)
	case "shift":
		p.work(len(p.params.known))
		n, err := 1, error(nil)
		if len(rest) > 0 {
			n, err = strconv.Atoi(rest[0].lit)
		}
		shifted := p.params.shift(n)
		if err != nil { // an unknown count: any parameter may be in any position
			shifted = params{known: p.params.known[:1], more: p.get("@")}
		}
		p.params = p.params.merge(shifted)
	case "export", "readonly", "local", "declare", "typeset", "integer", "float":
		var ops []declared
		for _, a := range rest {
			if n, ok := assignTarget(a.word); ok {
				ops = append(ops, declared{name: n, value: a.taint, assigns: true})
			} else if isOption(a) || a.isLit && strings.HasPrefix(a.lit, "+") {
				ops = append(ops, declared{option: a.lit})
			} else if a.isLit {
				ops = append(ops, declared{name: a.lit})
			}
		}
		return p.declare(name, ops)
	case "alias":
		for _, a := range rest {
			segs := segments(a.word)
			n, text, ok := strings.Cut(firstText(segs), "=")
			if !ok || n == "" {
				continue
			}
			if len(a.taint) > 0 {
				// The value would be part of the alias's text, which runs as code.
				c.report(a.taint, "alias", true, a.word, args[0].word, adviceFor(use{program: "alias", vars: a.taint.names()}))
			}
			for _, seg := range segs[1:] {
				if seg.expansion {
					seg.text = "x" // what the alias was given in place of an expansion
				}
				text += seg.text
			}
			p.aliases[n] = text
		}
	case "enable":
		names, _ := operands(rest, "f")
		if slices.ContainsFunc(rest, func(a arg) bool { return isOption(a) && strings.Contains(a.lit, "n") }) {
			for _, n := range names {
				p.disabled[n] = true
			}
		}
	case "disable":
		// Without -a, -f, -r, -s or -p, zsh's disable turns builtins off.
		if !slices.ContainsFunc(rest, func(a arg) bool { return isOption(a) && strings.ContainsAny(a.lit, "afrsp") }) {
			names, _ := operands(rest, "")
			for _, n := range names {
				p.disabled[n] = true
			}
		}
	case "shopt":
		names, _ := operands(rest, "")
		if slices.ContainsFunc(rest, func(a arg) bool { return a.lit == "-s" }) && slices.Contains(names, "expand_aliases") {
			p.expandAliases = true
		}
	case "setopt":
		for _, a := range rest {
			if strings.ReplaceAll(strings.ToLower(a.lit), "_", "") == "allexport" {
				p.allExport = true
			}
		}
	}
	return nil
}

// readOptions are the options of read that take a value, by shell.
var readOptions = map[string]string{"sh": "adinNptu", "bash": "adinNptu", "dash": "p", "zsh": "dktu"}

// operands returns the words after a builtin's options, and the value of each
// option in withValue that it reads.
func operands(args []arg, withValue string) ([]string, map[byte]string) {
	values := map[byte]string{}
	for i := 0; i < len(args); i++ {
		a := args[i].lit
		if !isOption(args[i]) {
			return lits(args[i:]), values
		}
		if a == "--" {
			return lits(args[i+1:]), values
		}
		for j := 1; j < len(a); j++ {
			if strings.IndexByte(withValue, a[j]) < 0 {
				continue
			}
			if j+1 < len(a) {
				values[a[j]] = a[j+1:]
			} else if i+1 < len(args) {
				i++
				values[a[j]] = args[i].lit
			}
			break
		}
	}
	return nil, values
}

// set reads set: its operands become the positional parameters, -a exports
// every later assignment, and set alone prints every variable.
func (c *checker) set(p *process, rest []arg) taint {
	if len(rest) == 0 {
		return p.all()
	}
	p.work(len(p.params.known))
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a.lit == "--" || a.lit == "-":
			p.params = p.params.merge(positionals(p.params.at(0), rest[i+1:]))
			return nil
		case !a.isLit || len(a.lit) < 2 || a.lit[0] != '-' && a.lit[0] != '+':
			p.params = p.params.merge(positionals(p.params.at(0), rest[i:]))
			return nil
		default:
			on := a.lit[0] == '-'
			if on && strings.Contains(a.lit[1:], "a") {
				p.allExport = true
			}
			if strings.Contains(a.lit[1:], "o") && i+1 < len(rest) {
				i++ // the option's name, as in -o pipefail
				if on && rest[i].lit == "allexport" {
					p.allExport = true
				}
			}
		}
	}
	return nil
}

// declared is one operand of export, local and the like: NAME=value, a bare
// NAME, or an option such as -x.
type declared struct {
	name, option string
	value        taint
	target       string // the variable a nameref names
	codes        []code // the texts NAME=value gives, if the check knows them
	assigns      bool
}

// declare records what export, local, declare and the like assign and export.
// Without names they print variables, as declare -p prints those it names.
func (p *process) declare(variant string, ops []declared) taint {
	export := variant == "export"
	nameref, print := false, false
	for _, d := range ops {
		if strings.HasPrefix(d.option, "-") {
			export = export || strings.Contains(d.option, "x")
			nameref = nameref || strings.Contains(d.option, "n")
			print = print || strings.Contains(d.option, "p")
		}
	}
	var out taint
	named := false
	for _, d := range ops {
		if d.name == "" {
			continue
		}
		named = true
		switch {
		case nameref && d.assigns:
			p.refs[d.name] = d.target
		case d.assigns:
			p.assignCode(d.name, d.value, d.codes)
		}
		if export {
			p.exported[d.name] = true
		}
		if print {
			out = out.union(p.get(d.name))
		}
	}
	if !named {
		if variant == "export" {
			return p.exportedValues()
		}
		return p.all()
	}
	return out
}

func (p *process) exportedValues() taint {
	return joinedEnv(p.exportedVars())
}

func (c *checker) declClause(p *process, d *syntax.DeclClause, in stream) taint {
	var ops []declared
	for _, a := range d.Args {
		if a.Name != nil {
			target, _ := literal(a.Value)
			ops = append(ops, declared{name: a.Name.Value, value: c.assignValue(p, a, in), target: target,
				assigns: !a.Naked, codes: c.literalCode(p, a)})
			continue
		}
		// An option, or "NAME=$value" in quotes.
		w := c.arg(p, a.Value, in)
		if name, ok := assignTarget(a.Value); ok {
			ops = append(ops, declared{name: name, value: w.taint, assigns: true})
		} else if w.isLit {
			ops = append(ops, declared{option: w.lit})
		}
	}
	return p.declare(d.Variant.Value, ops)
}

// program reads a command the shell executes. Each of its words is in its
// command line, and in those of the programs it starts with them, as env and
// nohup do.
func (c *checker) program(p *process, args []arg, env map[string]taint, in stream) taint {
	l := launched(args)
	var child map[string]taint
	// environ is the program's environment, made only for one that reads it.
	environ := func() map[string]taint {
		if child == nil {
			child = map[string]taint{}
			if !l.clear {
				child = p.environ(env)
			}
			for _, name := range l.unset {
				delete(child, name)
			}
			maps.Copy(child, l.set)
		}
		return child
	}

	c.reportWords(args, l)
	if l.xargs && len(in.taint) > 0 {
		// xargs makes what it reads into words of the program it runs.
		u := use{program: "echo", vars: in.taint.names()}
		if l.at < len(args) {
			u.program = display(args[l.at])
			u.words, u.held = fed(args[l.at:], l.marker, u.vars)
		}
		c.report(in.taint, u.program, false, args[0].word, args[0].word, adviceFor(u))
	}
	if l.script >= 0 {
		// watch runs its words, joined, as an sh script; those that hold a
		// value are in its command line already.
		if l.script < len(args) && len(joined(args[l.script:])) == 0 {
			codes, ok := c.codesOf(p, args[l.script:])
			if !ok {
				c.unknownCode(c.newProcess("sh", environ()), "watch", args[l.script].word)
			}
			for _, code := range codes {
				c.script(c.newProcess("sh", environ()), code.text, code.line, stream{})
			}
		}
		return nil
	}
	if l.at == len(args) {
		if l.last == "env" {
			return joinedEnv(environ()) // env alone prints its environment
		}
		return nil
	}
	prog := args[l.at]
	if !prog.isLit {
		return nil
	}
	name := path.Base(prog.lit)
	if shells[name] {
		return c.nested(p, args[l.at:], environ(), in)
	}
	for i, a := range args[l.at+1:] {
		// A shell given a script among another program's words, as in
		// find -exec sh -c SCRIPT, runs it with that program's environment.
		if a.isLit && shells[path.Base(a.lit)] {
			c.nested(p, args[l.at+1+i:], environ(), stream{})
			break
		}
	}
	// A program can read a descriptor that exec opened, through /dev/fd/3, or
	// any of them through a path the script makes as it runs.
	for _, a := range args[l.at+1:] {
		if n, ok := descriptor(a.lit); ok && a.isLit && n > 2 {
			in.taint = in.taint.union(p.fds[n])
		} else if !a.isLit && mayRead(segments(a.word)) {
			for _, t := range p.fds {
				in.taint = in.taint.union(t)
			}
		}
	}
	return printed(name, args[l.at+1:], environ, in)
}

// reportWords reports each word of a command that holds a value, as in the
// command line of the program it is a word of: the program the command runs,
// or a launcher in front of it, such as env for env NAME=value. One advice
// covers all the words of a program.
func (c *checker) reportWords(args []arg, l launch) {
	held := map[int][]int{}
	for i, a := range args {
		if len(a.taint) > 0 {
			held[l.owner[i]] = append(held[l.owner[i]], i)
		}
	}
	for _, owner := range slices.Sorted(maps.Keys(held)) {
		u := use{program: display(args[owner]), words: args[owner:]}
		var vars taint
		for _, i := range held[owner] {
			u.held = append(u.held, i-owner)
			vars = vars.union(args[i].taint)
		}
		u.vars = vars.names()
		if owner < l.at && l.at < len(args) {
			u.then = display(args[l.at])
		}
		fix := adviceFor(u)
		for _, i := range held[owner] {
			c.report(args[i].taint, u.program, false, args[i].word, args[0].word, fix)
		}
	}
}

func joinedEnv(env map[string]taint) taint {
	var t taint
	for _, v := range env {
		t = t.union(v)
	}
	return t
}

// nested reads a shell that process p starts: a new process that sees only
// its environment, with its own positional parameters, reading its script
// from -c or from stdin.
func (c *checker) nested(p *process, args []arg, env map[string]taint, in stream) taint {
	shell := path.Base(args[0].lit)
	child := c.newProcess(shell, env)
	at, fromStdin := scriptArg(shell, lits(args[1:]))
	switch {
	case at >= 0:
		script := args[1+at]
		if len(script.taint) > 0 {
			return nil // its values were in the shell's command line already
		}
		codes, ok := c.codesOf(p, args[1+at:2+at])
		if !ok {
			c.unknownCode(child, shell+" -c", script.word)
			return nil
		}
		var zero taint
		if 2+at < len(args) {
			zero = args[2+at].taint
		}
		var out taint
		for _, code := range codes {
			child := c.newProcess(shell, env)
			child.params = positionals(zero, args[min(3+at, len(args)):])
			out = out.union(c.script(child, code.text, code.line, in))
		}
		return out
	case fromStdin && len(in.taint) > 0:
		// The shell would run the value as code.
		c.report(in.taint, shell, true, args[0].word, args[0].word, adviceFor(use{program: shell, vars: in.taint.names()}))
	case fromStdin && in.literal:
		return c.script(child, in.text, in.line, stream{})
	}
	return nil
}

// printed returns what a program prints that may hold a value: what it read
// on stdin, for one that transforms its input, such as base64, and its
// environment's values, which environ makes, for one that prints them, such
// as printenv.
func printed(name string, args []arg, environ func() map[string]taint, in stream) taint {
	if (transformers[name] || awks[name]) && !readsStdin(name, args) {
		in = stream{} // it reads a file instead, or nothing, as jq -n does
	}
	switch {
	case name == "printenv":
		names, _ := operands(args, "")
		if len(names) == 0 {
			return joinedEnv(environ())
		}
		var t taint
		for _, n := range names {
			t = t.union(environ()[n])
		}
		return t
	case name == "envsubst":
		return in.taint.union(joinedEnv(environ()))
	case name == "gh" && len(args) > 1 && args[0].lit == "auth" && args[1].lit == "token":
		// gh auth token prints the token gh would use, from its environment.
		env := environ()
		return env["GH_TOKEN"].union(env["GITHUB_TOKEN"]).union(env["GH_ENTERPRISE_TOKEN"]).union(env["GITHUB_ENTERPRISE_TOKEN"])
	case name == "jq":
		return in.taint.union(readsEnv(args, environ, jqEnv))
	case awks[name]:
		return in.taint.union(readsEnv(args, environ, awkEnv))
	case transformers[name]:
		return in.taint
	}
	return nil
}

// Code in jq and awk programs that reads the environment, with the name it
// reads, if one: jq's env.NAME and $ENV.NAME, and awk's ENVIRON["NAME"].
var (
	jqEnv  = regexp.MustCompile(`(?:^|[^.\w$])(?:env|\$ENV)\b(?:\.([A-Za-z_]\w*)|\[\s*"([A-Za-z_]\w*)"\s*\])?`)
	awkEnv = regexp.MustCompile(`\bENVIRON\b(?:\[\s*"([A-Za-z_]\w*)"\s*\])?`)
)

// readsEnv returns the values of the environment, which environ makes, that
// a program's code reads.
func readsEnv(args []arg, environ func() map[string]taint, code *regexp.Regexp) taint {
	var t taint
	for _, a := range args {
		for _, m := range code.FindAllStringSubmatch(a.lit, -1) {
			name := strings.Join(m[1:], "")
			if name == "" {
				return joinedEnv(environ())
			}
			t = t.union(environ()[name])
		}
	}
	return t
}

// A launch is where a command's words name the program it runs, past the
// launchers in front of it, such as env, nohup and xargs, which run it with
// the words after their own.
type launch struct {
	at     int              // the program's word, or len(args) if there is none
	owner  []int            // the launcher or program whose own word each word is
	last   string           // the last launcher, as env alone prints its environment
	set    map[string]taint // env and sudo's NAME=value
	unset  []string         // env -u NAME
	clear  bool             // env -i
	xargs  bool             // whether xargs makes what it reads into words
	marker string           // the text that xargs -I or -J puts what it reads in place of
	script int              // where watch's words start, which it runs as a script, or -1
}

func launched(args []arg) launch {
	l := launch{owner: make([]int, len(args)), set: map[string]taint{}, script: -1}
	words := lits(args)
	i := 0
	for i < len(args) && args[i].isLit {
		name := path.Base(args[i].lit)
		spec, ok := launchers[name]
		if !ok {
			break
		}
		start := i
		var opts []option
		i, opts = options(words, i+1, spec)
		l.last = name
		switch name {
		case "env":
			for _, o := range opts {
				switch o.name {
				case "-i", "--ignore-environment":
					l.clear = true
				case "-u", "--unset":
					l.unset = append(l.unset, o.value)
				case "-S", "--split-string":
					i = len(args) // env splits a string into the command, which it cannot follow
				}
			}
			if i < len(args) && words[i] == "-" {
				l.clear, i = true, i+1
			}
			fallthrough
		case "sudo":
			// Unlike a shell, they take any name before an =, such as A.B.
			for ; i < len(args); i++ {
				n, _, ok := strings.Cut(leading(args[i]), "=")
				if !ok || n == "" {
					break
				}
				l.set[n] = l.set[n].union(args[i].taint)
			}
		case "timeout", "gtimeout":
			i = min(i+1, len(args)) // the duration
		case "xargs":
			l.xargs = true
			for _, o := range opts {
				if o.name == "-I" || o.name == "-J" {
					l.marker = o.value
				}
			}
		case "watch":
			if !slices.ContainsFunc(opts, func(o option) bool { return o.name == "-x" || o.name == "--exec" }) {
				l.script = i
				i = len(args)
			}
		}
		for j := start; j < i; j++ {
			l.owner[j] = start
		}
	}
	l.at = i
	for j := i; j < len(args); j++ {
		l.owner[j] = i
	}
	return l
}

// An option is one a program read, with its value if it takes one.
type option struct{ name, value string }

// optionSpec names the options of a program that take a value: short letters,
// and long names, as --signal KILL.
type optionSpec struct {
	short string
	long  []string
}

// options reads a program's options from words[i] on, as getopt does, and
// returns where its operands start.
func options(words []string, i int, spec optionSpec) (int, []option) {
	var opts []option
	for ; i < len(words); i++ {
		w := words[i]
		if w == "--" {
			return i + 1, opts
		}
		if len(w) < 2 || w[0] != '-' {
			return i, opts
		}
		if long, ok := strings.CutPrefix(w, "--"); ok {
			name, value, inline := strings.Cut(long, "=")
			if !inline && slices.Contains(spec.long, name) && i+1 < len(words) {
				i++
				value = words[i]
			}
			opts = append(opts, option{"--" + name, value})
			continue
		}
		for j := 1; j < len(w); j++ {
			if strings.IndexByte(spec.short, w[j]) < 0 {
				opts = append(opts, option{"-" + w[j:j+1], ""})
				continue
			}
			value := w[j+1:]
			if value == "" && i+1 < len(words) {
				i++
				value = words[i]
			}
			opts = append(opts, option{"-" + w[j:j+1], value})
			break
		}
	}
	return i, opts
}

// word returns what a word's value may hold, and reads the commands inside
// it, such as $(...), whose stdin is in.
func (c *checker) word(p *process, w *syntax.Word, in stream) taint {
	if w == nil || len(w.Parts) == 0 || !c.spend(span(w)/bytesPerStep) {
		return nil
	}
	var t taint
	for _, part := range w.Parts {
		t = t.union(c.part(p, part, in))
	}
	return t
}

// span is how many bytes of the script a node takes up.
func span(n syntax.Node) int {
	return max(int(n.End().Offset())-int(n.Pos().Offset()), 0)
}

func (c *checker) part(p *process, part syntax.WordPart, in stream) taint {
	if !c.spend(1) {
		return nil
	}
	switch x := part.(type) {
	case *syntax.DblQuoted:
		var t taint
		for _, q := range x.Parts {
			t = t.union(c.part(p, q, in))
		}
		return t
	case *syntax.ParamExp:
		return c.param(p, x, in)
	case *syntax.CmdSubst:
		if st := x.Stmts; len(st) == 1 && st[0].Cmd == nil && len(st[0].Redirs) == 1 &&
			st[0].Redirs[0].Op == syntax.RdrIn && p.shell != "dash" {
			// $(<FILE) is what FILE holds, in every shell but dash.
			in.taint = in.taint.union(p.fds[0])
			return c.redirect(p.fork(), st[0], in).stdin.taint
		}
		return c.stmts(p.fork(), x.Stmts, in) // what reaches its stdout
	case *syntax.ProcSubst:
		c.stmts(p.fork(), x.Stmts, in) // the program gets a path, not the output
	case *syntax.ArithmExp:
		return c.arithm(p, x.X, in)
	}
	return nil
}

func (c *checker) param(p *process, pe *syntax.ParamExp, in stream) taint {
	var inner taint // what words inside it hold, as in ${X:-$T}
	if pe.Exp != nil {
		inner = c.word(p, pe.Exp.Word, in)
	}
	if pe.Repl != nil {
		c.word(p, pe.Repl.Orig, in)
		inner = inner.union(c.word(p, pe.Repl.With, in))
	}
	c.arithm(p, pe.Index, in)
	if pe.Slice != nil {
		c.arithm(p, pe.Slice.Offset, in)
		c.arithm(p, pe.Slice.Length, in)
	}
	var own taint
	switch {
	case pe.Length || pe.IsSet || pe.Names != 0 || pe.Excl && pe.Index != nil:
		return nil // ${#T}, ${+T}, ${!prefix*} and ${!array[@]} hold no part of a value
	case pe.Excl || pe.Flags != nil && strings.ContainsAny(pe.Flags.Value, "Pe"):
		own = p.all() // ${!name}, and zsh's ${(P)name} and ${(e)name}, expand another
	case pe.NestedParam != nil:
		own = c.part(p, pe.NestedParam, in)
	case pe.Param != nil:
		own = p.get(pe.Param.Value)
	}
	if pe.Exp != nil && (pe.Exp.Op == syntax.AlternateUnset || pe.Exp.Op == syntax.AlternateUnsetOrNull) {
		return inner // ${T:+word} is the word
	}
	if pe.Exp != nil && (pe.Exp.Op == syntax.AssignUnset || pe.Exp.Op == syntax.AssignUnsetOrNull) &&
		pe.Param != nil && syntax.ValidName(pe.Param.Value) {
		p.assign(pe.Param.Value, inner) // ${X:=word} also assigns the word to X
	}
	return own.union(inner)
}

// arithm returns what an arithmetic expression may hold. It is a number, but
// a numeric secret, such as a PIN, survives arithmetic.
func (c *checker) arithm(p *process, e syntax.ArithmExpr, in stream) taint {
	switch x := e.(type) {
	case *syntax.Word:
		if name := x.Lit(); syntax.ValidName(name) {
			return p.get(name)
		}
		// let "n = PIN" reads its quoted text as arithmetic.
		if text, ok := literal(x); ok && text != x.Lit() && c.spend(parseSteps(text)) {
			if e, err := syntax.NewParser().Arithmetic(strings.NewReader(text)); err == nil {
				return c.arithm(p, e, in)
			}
		}
		return c.word(p, x, in)
	case *syntax.BinaryArithm:
		t := c.arithm(p, x.X, in).union(c.arithm(p, x.Y, in))
		if w, ok := x.X.(*syntax.Word); ok && arithmAssigns[x.Op] && syntax.ValidName(w.Lit()) {
			p.assign(w.Lit(), t)
		}
		return t
	case *syntax.UnaryArithm:
		return c.arithm(p, x.X, in)
	case *syntax.ParenArithm:
		return c.arithm(p, x.X, in)
	case *syntax.FlagsArithm:
		return c.arithm(p, x.X, in)
	}
	return nil
}

// literal returns a word's value after quote removal, if it has no expansions.
func literal(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch x := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescape(x.Value, ""))
		case *syntax.SglQuoted:
			if x.Dollar && strings.Contains(x.Value, `\`) {
				return "", false // $'...' escapes, which are not decoded here
			}
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				lit, ok := q.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(unescape(lit.Value, "$`\"\\\n"))
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// unescape removes the backslashes that quote removal does: those before any
// of escapes, or before any character at all when escapes is "", as outside
// quotes. A backslash and a newline join two lines.
func unescape(s string, escapes string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (escapes == "" || strings.IndexByte(escapes, s[i+1]) >= 0) {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var assignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\[[^]]*\])?\+?=`)

// assignTarget returns NAME for a word that starts NAME=, as export takes it.
func assignTarget(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
parts:
	for _, part := range w.Parts {
		switch x := part.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				lit, ok := q.(*syntax.Lit)
				if !ok {
					break parts
				}
				b.WriteString(lit.Value)
			}
		default:
			break parts
		}
	}
	m := assignment.FindStringSubmatch(b.String())
	if m == nil {
		return "", false
	}
	return m[1], true
}

// programName is what display shows of a program's name, if a message may
// show it.
var programName = regexp.MustCompile(`^[A-Za-z0-9._+\[-]+$`)

// shownName reports whether a message may show a program's or a header's
// name: not one that could be a value pasted in its place, which is longer
// than 24 bytes or has digits among capitals, as keys do.
func shownName(name string) bool {
	return len(name) <= 24 && !(strings.ContainsAny(name, "0123456789") && strings.ContainsFunc(name, func(r rune) bool { return r >= 'A' && r <= 'Z' }))
}

// display names the program a command word runs, as a message shows it: its
// base name, $NAME for one named by a variable, or "a program".
func display(a arg) string {
	if a.isLit {
		if name := strings.TrimPrefix(path.Base(a.lit), "="); programName.MatchString(name) && shownName(name) {
			return name
		}
		return "a program"
	}
	if a.word != nil && len(a.word.Parts) == 1 {
		if pe, ok := a.word.Parts[0].(*syntax.ParamExp); ok && pe.Param != nil && syntax.ValidName(pe.Param.Value) {
			return "$" + pe.Param.Value
		}
	}
	return "a program"
}

func setOf(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

var (
	// shells are the shells whose scripts are read.
	shells = setOf("sh", "bash", "dash", "zsh")

	// builtins are the commands all four shells run themselves, so the words
	// given them reach no program's command line. A path such as /bin/echo, or
	// a builtin's name after exec or env, names a program.
	builtins = setOf(":", ".", "[", "alias", "bg", "break", "cd", "command", "continue",
		"echo", "eval", "exec", "exit", "export", "false", "fg", "getopts", "hash", "jobs",
		"kill", "local", "printf", "pwd", "read", "readonly", "return", "set", "shift",
		"test", "times", "trap", "true", "type", "ulimit", "umask", "unalias", "unset", "wait")
	// bashBuiltins are bash's others. sh on macOS is bash in POSIX mode.
	bashBuiltins = setOf("bind", "builtin", "caller", "compgen", "complete", "compopt",
		"declare", "dirs", "disown", "enable", "fc", "help", "history", "let", "logout",
		"mapfile", "popd", "pushd", "readarray", "shopt", "source", "suspend", "typeset")
	// zshBuiltins are zsh's others.
	zshBuiltins = setOf("autoload", "bindkey", "builtin", "declare", "dirs", "disable",
		"disown", "emulate", "enable", "fc", "float", "functions", "history", "integer",
		"let", "limit", "nocorrect", "noglob", "popd", "print", "pushd", "rehash", "sched",
		"setopt", "source", "typeset", "unfunction", "unhash", "unlimit", "unsetopt",
		"vared", "whence", "where", "which", "zmodload", "zparseopts", "zstyle")
	// special are POSIX's special builtins, whose assignments outlast them.
	special = setOf(":", ".", "break", "continue", "eval", "exec", "exit", "export",
		"readonly", "return", "set", "shift", "times", "trap", "unset")

	// launchers are programs that run the command after their own words.
	launchers = map[string]optionSpec{
		"caffeinate": {short: "tw"},
		"doas":       {short: "uC"},
		"env":        {short: "uCPS", long: []string{"unset", "chdir", "split-string"}},
		"gtimeout":   {short: "ks", long: []string{"kill-after", "signal"}},
		"nice":       {short: "n", long: []string{"adjustment"}},
		"nohup":      {},
		"stdbuf":     {short: "ioe", long: []string{"input", "output", "error"}},
		"sudo":       {short: "ugpCDhrtTU", long: []string{"user", "group", "prompt", "close-from", "chdir", "host", "role", "type", "command-timeout", "other-user"}},
		"time":       {short: "fo", long: []string{"format", "output"}},
		"timeout":    {short: "ks", long: []string{"kill-after", "signal"}},
		"watch":      {short: "nq", long: []string{"interval", "equexit"}},
		"xargs":      {short: "aEdIJLnPRs", long: []string{"arg-file", "delimiter", "max-lines", "max-args", "max-procs", "max-chars"}},
	}

	// transformers are programs whose output is made of their input, so it holds
	// any value they read. Other programs' output, such as curl's response, is
	// taken not to.
	transformers = setOf("base32", "base64", "basenc", "bunzip2", "bzcat", "bzip2", "cat",
		"column", "cut", "dd", "egrep", "expand", "fgrep", "fmt", "fold", "grep", "gunzip",
		"gzcat", "gzip", "head", "hexdump", "iconv", "jq", "lz4", "lz4cat", "nl", "node", "od",
		"openssl", "paste", "perl", "pr", "python", "python3", "rev", "ruby", "sed", "sort",
		"strings", "tac", "tail", "tee", "tr", "unexpand", "uniq", "unlz4", "unxz", "unzstd",
		"xxd", "xz", "xzcat", "yq", "zcat", "zstd", "zstdcat")
	awks = setOf("awk", "gawk", "mawk", "nawk")

	arithmAssigns = map[syntax.BinAritOperator]bool{syntax.Assgn: true, syntax.AddAssgn: true,
		syntax.SubAssgn: true, syntax.MulAssgn: true, syntax.QuoAssgn: true, syntax.RemAssgn: true,
		syntax.AndAssgn: true, syntax.OrAssgn: true, syntax.XorAssgn: true, syntax.ShlAssgn: true,
		syntax.ShrAssgn: true, syntax.AndBoolAssgn: true, syntax.OrBoolAssgn: true,
		syntax.XorBoolAssgn: true, syntax.PowAssgn: true}
)
