package doctor

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/veilux-lab/keyward/internal/migrate"
)

// width is where the output wraps, so it reads whole in a terminal.
const width = 100

// minWrap is the fewest columns text wraps in beside other columns.
const minWrap = 30

// Style is what a part of the output is, for Format.Paint to show.
type Style int

const (
	plain Style = iota
	// Heading is a section's heading.
	Heading
	// OK, Warning and Problem mark a check that passed, one that needs attention,
	// and one that failed.
	OK
	Warning
	Problem
	// Command is what the reader acts on: a location, a tag or a command.
	Command
	// Quiet is what explains: a reason, a detail or a note.
	Quiet
)

// Format says how to render: paths under Home as ~/, and each part as Paint
// styles it, or plain where Paint is nil.
type Format struct {
	Home  string
	Paint func(Style, string) string
}

// Status is how a check came out.
type Status int

const (
	Pass Status = iota
	Attention
	Fail
)

// Check is a line of the checklist: what was checked, and how it came out.
type Check struct {
	Status      Status
	Label, Text string
}

// Render renders what needs action, a section for each kind. Problems come
// first, because a dangling reference breaks a command now while an orphan costs
// a line of output. It is empty when nothing needs action.
func (r *Report) Render(f Format) string {
	var sections []string
	if n := len(r.Dangling); n > 0 {
		rows := make([][]cell, n)
		for i, d := range r.Dangling {
			rows[i] = []cell{f.location(d), {plain, "cap://" + d.Name}, {Command, "keyward add " + d.Name}}
		}
		sections = append(sections, f.heading(Fail, fmt.Sprintf("%d reference(s) point at secrets that are not in the vault", n))+f.table(rows, -1))
	}
	if n := len(r.Malformed); n > 0 {
		rows := make([][]cell, n)
		for i, m := range r.Malformed {
			rows[i] = []cell{f.location(m), {plain, "cap://" + m.Name}}
		}
		sections = append(sections, f.heading(Fail, fmt.Sprintf("%d malformed reference(s), which will fail when used", n))+f.table(rows, -1))
	}

	certain, possible := r.plaintextEntries()
	if certain.lines > 0 {
		// Rotating leaves the vault with the old value. The user makes these changes;
		// an agent that opens a line reads the secret.
		sections = append(sections, f.heading(Fail, fmt.Sprintf("%d credential(s) in plaintext", certain.lines))+f.entries(certain.entries)+"\n"+
			f.fixes("To fix each:", "every line", certain.entries)+
			f.paragraph(plain, "Then rotate each one, and store its new value with keyward add --force NAME.")+
			f.paragraph(Warning, "AI agents must not open these lines or print these configs; ask the user to fix them."))
	}
	if possible.lines > 0 {
		s := f.heading(Attention, fmt.Sprintf("%d value(s) that may be credentials", possible.lines)) + f.entries(possible.entries) + "\n" +
			f.fixes("If one is a credential:", "each line that is one", possible.entries) +
			f.paragraph(plain, "Rotate each one that is a credential, and store its new value with keyward add --force NAME.")
		if possible.markable {
			s += f.paragraph(plain, "If one holds no secret, end its line with # "+migrate.IgnoreMarker+" yourself, "+possible.eachLine()+
				"and keyward leaves the line alone (shell and .env files only); an AI agent must not.")
		}
		if possible.paired {
			s += f.paragraph(plain, "Marking leaves the whole line alone, so mark a line listed twice, for its value and for the comment beside it, only once neither holds a secret.")
		}
		sections = append(sections, s+f.paragraph(Warning, "AI agents must not open these lines or print these configs; ask the user to judge them."))
	}

	if n := len(r.Orphaned); n > 0 {
		rows := make([][]cell, n)
		for i, o := range r.Orphaned {
			rows[i] = []cell{{plain, o.Name}, {Quiet, f.Tilde(o.Detail)}, {Command, "keyward rm " + o.Name}}
		}
		sections = append(sections, f.heading(Attention, fmt.Sprintf("%d secret(s) whose source no longer references them", n))+f.table(rows, 1))
	}
	if n := len(r.Unknown); n > 0 {
		rows := make([][]cell, n)
		for i, u := range r.Unknown {
			rows[i] = []cell{{plain, u.Name}, {Quiet, f.Tilde(u.Detail)}}
		}
		sections = append(sections, f.heading(Attention, fmt.Sprintf("%d secret(s) nothing scanned refers to, which may still be in use", n))+f.table(rows, 1))
	}
	return strings.Join(sections, "\n")
}

// Summary renders the notes but empty ones, the files read, and a line for each
// check.
func (r *Report) Summary(f Format, checks []Check, notes []string) string {
	var b strings.Builder
	for _, note := range notes {
		if note != "" {
			b.WriteString(f.block("", 0, Quiet, "Note: "+note) + "\n")
		}
	}
	// Without the files read, "unreferenced" reads as "unused".
	const title = "keyward doctor"
	at := len(title) + 2
	b.WriteString(f.paint(Heading, title) + "  " + f.files("read", r.Scanned, at))
	if len(r.Absent) > 0 {
		b.WriteString(spaces(at) + f.files("not read", r.Absent, at))
	}
	labelW := 0
	for _, c := range checks {
		labelW = max(labelW, runes(c.Label))
	}
	for i, c := range checks {
		label := c.Label
		if i > 0 && label == checks[i-1].Label {
			label = ""
		}
		b.WriteString(f.block("  "+f.icon(c.Status)+" "+f.pad(cell{plain, label}, labelW)+"  ", 4+labelW+2, plain, c.Text))
	}
	return b.String()
}

// Verdict sums up the checks: the problems found, or that there are none and how
// many checks need attention.
func (f Format) Verdict(checks []Check, problems []string) string {
	if len(problems) > 0 {
		var b strings.Builder
		for i, line := range wrap(strings.Fields("Problems found: "+strings.Join(problems, "; ")+"."), width-2) {
			if i == 0 {
				b.WriteString(f.paint(Problem, f.paint(Heading, "✗ "+line)) + "\n")
			} else {
				b.WriteString("  " + f.paint(Problem, f.paint(Heading, line)) + "\n")
			}
		}
		return b.String()
	}
	attention := 0
	for _, c := range checks {
		if c.Status == Attention {
			attention++
		}
	}
	verdict := f.paint(OK, f.paint(Heading, "✓ No problems found."))
	switch {
	case attention == 1:
		verdict += " " + f.paint(Quiet, "1 check needs attention.")
	case attention > 1:
		verdict += " " + f.paint(Quiet, fmt.Sprintf("%d checks need attention.", attention))
	}
	return verdict + "\n"
}

// Alert renders a problem the report does not hold, such as a secret in a
// running program's command line, as a section of its own.
func (f Format) Alert(heading, advice string) string {
	return f.heading(Fail, heading) + f.paragraph(plain, advice)
}

// entries renders the rows of a list of credentials in columns: where, the tag,
// what holds it, and why it looks like one, which wraps in a column of its own.
// An MCP server's row has its reason and fix under what holds it.
func (f Format) entries(list []entry) string {
	tagW := 0
	for _, e := range list {
		tagW = max(tagW, runes(e.tag))
	}
	// A location too long to leave what follows it minWrap columns has a line of
	// its own, so it does not push the other rows right.
	locW := 0
	for _, e := range list {
		if w := runes(f.Tilde(e.where)); 2+w+2+tagW+2 <= width-minWrap {
			locW = max(locW, w)
		}
	}
	whatAt := 2 + locW + 2 + tagW + 2
	whatW := 0
	for _, e := range list {
		if w := runes(f.Tilde(e.what)); e.fix == "" && whatAt+w+2 <= width-minWrap {
			whatW = max(whatW, w)
		}
	}
	// A reason keeps minWrap columns even where no what leaves it room beside.
	reasonAt := min(whatAt+whatW+2, width-minWrap)
	var b strings.Builder
	for _, e := range list {
		where := f.Tilde(e.where)
		lead := "  " + f.pad(cell{Command, where}, locW) + "  "
		if runes(where) > locW {
			b.WriteString("  " + f.paint(Command, where) + "\n")
			lead = spaces(2 + locW + 2)
		}
		lead += f.pad(cell{Command, e.tag}, tagW) + "  "
		what := f.Tilde(e.what)
		switch {
		case e.fix != "":
			b.WriteString(f.block(lead, whatAt, plain, what) + f.block(spaces(whatAt), whatAt, Quiet, e.reason) + f.block(spaces(whatAt), whatAt, plain, f.Tilde(e.fix)))
		case whatAt+runes(what)+2 <= reasonAt:
			b.WriteString(f.block(lead+f.pad(cell{plain, what}, reasonAt-whatAt), reasonAt, Quiet, e.reason))
		default:
			b.WriteString(lead + what + "\n" + f.block(spaces(reasonAt), reasonAt, Quiet, e.reason))
		}
	}
	return b.String()
}

// fixes is the legend of a list: how to fix a row of each tag it uses but an MCP
// server's, and an example of the first value whose name can be a reference's.
// inRange says which lines of a range to remove. It is empty where no row is a
// line's.
func (f Format) fixes(intro, inRange string, list []entry) string {
	used, files := map[string]bool{}, map[string]bool{}
	ranged, example := false, ""
	for _, e := range list {
		used[e.tag] = true
		ranged = ranged || e.lines > 1
		if e.tag == tagMigrate {
			files[e.file] = true
		}
		if example == "" && (e.tag == tagMigrate || e.tag == tagAdd) {
			if ref, err := migrate.RefName(e.what); err == nil {
				// keyward add only stores a copy, so the variable is set to the reference too.
				example = "e.g. keyward add " + ref + " and set " + e.what + " to 'cap://" + ref + "'"
			}
		}
	}
	file := "on the file it is in"
	if len(files) == 1 {
		for path := range files {
			file = f.Tilde(path)
		}
	}
	store := "store it with keyward add NAME and set the variable to 'cap://NAME'"
	edit := "remove it by hand in an editor"
	if ranged {
		edit += " (in a range, " + inRange + ")"
	}
	var lines [][2]string
	for _, l := range [][2]string{
		{tagMigrate, "move it with keyward migrate " + file + " (preview with --dry-run), or " + store},
		{tagAdd, store + "; migrate moves only values it is sure of"},
		{tagEdit, edit},
	} {
		if used[l[0]] {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	tagW := 0
	for _, l := range lines {
		tagW = max(tagW, runes(l[0]))
	}
	b := "  " + intro + "\n"
	for _, l := range lines {
		b += f.block("    "+f.pad(cell{Command, l[0]}, tagW)+"  ", 4+tagW+2, plain, l[1])
	}
	if example != "" {
		b += f.block("    ", 4, Quiet, example)
	}
	return b
}

// files lists paths after what was done with them, wrapped under the first. A
// comma ends each but the last, as a path may hold a space.
func (f Format) files(done string, paths []string, at int) string {
	words := []string{"no files"}
	if len(paths) > 0 {
		words = make([]string, len(paths))
		for i, p := range paths {
			words[i] = f.Tilde(p)
			if i < len(paths)-1 {
				words[i] += ","
			}
		}
	}
	at += runes(done) + 1
	var b strings.Builder
	for i, line := range wrap(words, width-at) {
		if i == 0 {
			b.WriteString(f.paint(Quiet, done+" "+line) + "\n")
		} else {
			b.WriteString(spaces(at) + f.paint(Quiet, line) + "\n")
		}
	}
	return b.String()
}

// cell is text in a style.
type cell struct {
	style Style
	text  string
}

// table renders rows in columns, those of column flex wrapping in what the others
// leave (-1 for none). Columns that do not fit go under their row, so a long name
// does not run past the width.
func (f Format) table(rows [][]cell, flex int) string {
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			widths[i] = max(widths[i], runes(c.text))
		}
	}
	beside, used := 1, 2+widths[0]
	for ; beside < len(widths); beside++ {
		w := widths[beside]
		if beside == flex {
			w = min(w, minWrap)
		}
		if used+2+w > width {
			break
		}
		used += 2 + w
	}
	wraps := flex >= 0 && flex < beside
	if wraps {
		// flex was counted at minWrap at most, and takes what the others leave.
		widths[flex] = min(widths[flex], width-used+min(widths[flex], minWrap))
	}
	var b strings.Builder
	for _, row := range rows {
		lines := []string{""}
		if wraps {
			lines = wrap(strings.Fields(row[flex].text), widths[flex])
		}
		for i, text := range lines {
			cells := make([]string, beside)
			for j, c := range row[:beside] {
				switch {
				case j == flex:
					c.text = text
				case i > 0:
					c.text = ""
				}
				cells[j] = f.pad(c, widths[j])
			}
			b.WriteString(strings.TrimRight("  "+strings.Join(cells, "  "), " ") + "\n")
		}
		for _, c := range row[beside:] {
			b.WriteString(f.block("    ", 4, c.style, c.text))
		}
	}
	return b.String()
}

// location is where a reference is, as the reader opens it.
func (f Format) location(ref Reference) cell {
	return cell{Command, f.Tilde(fmt.Sprintf("%s:%d", ref.File, ref.Line))}
}

// heading starts a section: its icon, then its text in bold.
func (f Format) heading(s Status, text string) string {
	return f.block(f.icon(s)+" ", 2, Heading, text)
}

// paragraph is text in style, wrapped under a section's heading.
func (f Format) paragraph(style Style, text string) string {
	return f.block("  ", 2, style, text)
}

// icon marks how a check came out, in its colour.
func (f Format) icon(s Status) string {
	switch s {
	case Fail:
		return f.paint(Problem, "✗")
	case Attention:
		return f.paint(Warning, "!")
	}
	return f.paint(OK, "✓")
}

// block wraps text in style from column at, its first line after lead, which
// fills the columns before it.
func (f Format) block(lead string, at int, style Style, text string) string {
	var b strings.Builder
	for i, line := range wrap(strings.Fields(text), width-at) {
		if i > 0 {
			lead = spaces(at)
		}
		b.WriteString(lead + f.paint(style, line) + "\n")
	}
	return b.String()
}

// pad is c painted and padded to w columns. It is measured before it is
// painted, so escapes never move a column.
func (f Format) pad(c cell, w int) string {
	return f.paint(c.style, c.text) + spaces(w-runes(c.text))
}

func (f Format) paint(s Style, text string) string {
	if f.Paint == nil || s == plain || text == "" {
		return text
	}
	return f.Paint(s, text)
}

// Tilde shows paths under Home in s as ~/. Such a path starts s or follows a
// space or a parenthesis, so one that holds Home's further in, as an old disk's,
// stays as it is.
func (f Format) Tilde(s string) string {
	if f.Home == "" {
		return s
	}
	if rest, ok := strings.CutPrefix(s, f.Home+"/"); ok {
		s = "~/" + rest
	}
	for _, before := range []string{" ", "("} {
		s = strings.ReplaceAll(s, before+f.Home+"/", before+"~/")
	}
	return s
}

// wrap joins words into lines at most width runes long, breaking none.
func wrap(words []string, width int) []string {
	var lines []string
	line := ""
	for _, w := range words {
		if line != "" && runes(line)+1+runes(w) > width {
			lines, line = append(lines, line), ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	return append(lines, line)
}

func runes(s string) int { return utf8.RuneCountInString(s) }

func spaces(n int) string { return strings.Repeat(" ", max(n, 0)) }
