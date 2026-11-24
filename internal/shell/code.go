package shell

import (
	"fmt"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A code is text a variable may hold that a script could run as code, as
// eval "$cmd" does, with the line of the outermost script it starts on.
type code struct {
	text string
	line int
}

// maxCodes bounds the texts the check keeps for what one variable or word may
// hold; past it, the text is one the check cannot know. maxText bounds the
// bytes of the texts that variables keep in all, as an assignment such as
// a1="$a0$a0" doubles what a variable holds; past it, the check gives up.
const (
	maxCodes = 4
	maxText  = 1 << 20
)

// assignCode records that name may now hold t, as well as what it held, and
// that its text may be any of codes, or text the check cannot know if codes
// is nil. Once a variable may hold such text, it always may.
func (p *process) assignCode(name string, t taint, codes []code) {
	if len(t) > 0 {
		p.vars[name] = p.vars[name].union(t)
	}
	if p.allExport {
		p.exported[name] = true
	}
	known, ok := p.codes[name]
	if codes == nil || ok && known == nil {
		p.codes[name] = nil
		return
	}
	for _, c := range codes {
		if !slices.Contains(known, c) {
			known = append(slices.Clip(known), c) // a loop's next pass assigns the same
			*p.text += len(c.text)
		}
	}
	if len(known) > maxCodes || *p.text > maxText {
		known = nil
	}
	p.codes[name] = known
}

// codesOf returns the texts that words, joined with spaces, may make, if the
// check can know them: the words' literal text, a variable's literal text, as
// cmd='...' gives it, and what cat prints of a here-document of literal text.
func (c *checker) codesOf(p *process, words []arg) ([]code, bool) {
	out := []code{{line: int(words[0].word.Pos().Line())}}
	for i, w := range words {
		if i > 0 && !c.addCodes(&out, []code{{text: " "}}) {
			return nil, false
		}
		if w.isLit && !c.addCodes(&out, []code{{text: w.lit}}) || !w.isLit && !c.addCode(p, &out, w.word.Parts, "") {
			return nil, false
		}
	}
	return out, true
}

func (c *checker) addCode(p *process, out *[]code, parts []syntax.WordPart, escapes string) bool {
	for _, part := range parts {
		var next []code
		switch x := part.(type) {
		case *syntax.Lit:
			next = []code{{text: unescape(x.Value, escapes)}}
		case *syntax.SglQuoted:
			if x.Dollar && strings.Contains(x.Value, `\`) {
				return false // $'...' escapes, which are not decoded here
			}
			next = []code{{text: x.Value}}
		case *syntax.DblQuoted:
			if !c.addCode(p, out, x.Parts, "$`\"\\\n") {
				return false
			}
			continue
		case *syntax.ParamExp:
			if x.Param == nil || expansion(x) != "$"+x.Param.Value {
				return false
			}
			if next = p.codes[x.Param.Value]; next == nil {
				return false
			}
		case *syntax.CmdSubst:
			text, line, ok := catText(x)
			if !ok {
				return false
			}
			next = []code{{text: text, line: line}}
		default:
			return false
		}
		if !c.addCodes(out, next) {
			return false
		}
	}
	return true
}

// addCodes appends each of next to each text in out, while there are no more
// than maxCodes of them and variables keep no more than maxText, and counts
// each text it makes as work.
func (c *checker) addCodes(out *[]code, next []code) bool {
	var joined []code
	for _, a := range *out {
		for _, b := range next {
			if n := len(a.text) + len(b.text); c.text > maxText || !c.spend(n/bytesPerStep) {
				return false
			}
			if a.text == "" && b.line > 0 {
				a.line = b.line // where the text starts is where it was written
			}
			joined = append(joined, code{text: a.text + b.text, line: a.line})
		}
	}
	*out = joined
	return len(joined) <= maxCodes
}

// literalCode returns the texts a plain assignment NAME=WORD gives, if the
// check can know them.
func (c *checker) literalCode(p *process, a *syntax.Assign) []code {
	if a.Value == nil || a.Array != nil || a.Index != nil || a.Append || a.Naked {
		return nil
	}
	lit, ok := literal(a.Value)
	codes, _ := c.codesOf(p, []arg{{word: a.Value, lit: lit, isLit: ok}})
	return codes
}

// catText returns what $(cat <<'EOF' ... EOF) prints, a here-document of
// literal text without its trailing newlines, and the line it starts on.
func catText(cs *syntax.CmdSubst) (string, int, bool) {
	if len(cs.Stmts) != 1 {
		return "", 0, false
	}
	st := cs.Stmts[0]
	ce, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Assigns) > 0 || len(ce.Args) != 1 || ce.Args[0].Lit() != "cat" || len(st.Redirs) != 1 {
		return "", 0, false
	}
	r := st.Redirs[0]
	if r.Op != syntax.Hdoc && r.Op != syntax.DashHdoc || r.Hdoc == nil {
		return "", 0, false
	}
	text, ok := hereText(r)
	return strings.TrimRight(text, "\n"), int(r.Hdoc.Pos().Line()), ok
}

// literalTexts returns the text that a script writes literally, as in single
// quotes, which it could run as code, where it could name a variable: each
// piece with a $.
func literalTexts(f *syntax.File) []string {
	var out []string
	syntax.Walk(f, func(n syntax.Node) bool {
		var text string
		switch x := n.(type) {
		case *syntax.Lit:
			text = x.Value
		case *syntax.SglQuoted:
			text = x.Value
		}
		if strings.Contains(text, "$") {
			out = append(out, text)
		}
		return true
	})
	return out
}

// unknownCode records that p runs code the check cannot know, as eval "$(...)"
// does, from the word at. The code could be any literal text of the script.
func (c *checker) unknownCode(p *process, program string, at *syntax.Word) {
	c.mayRun(p, c.literals, unreadable{fmt.Sprintf("line %d: %s runs code made as the script runs", at.Pos().Line(), program), toWrite})
}

// mayRun records that p may run any of texts as code the check does not
// read, which is an error, as for a script that cannot be read, if one names
// a variable that holds a value, or a resolved one as a word.
func (c *checker) mayRun(p *process, texts []string, why unreadable) {
	for _, text := range texts {
		// Each text costs a step however short, or a script of many short
		// literals could be scanned again at every call for free.
		if !c.spend(1 + len(text)/bytesPerStep) {
			return
		}
		if p.names(text) || mentions(text, c.resolved) {
			c.cannotRead(p, text, why)
			return
		}
	}
}
