package doctor_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/migrate"
	"github.com/veilux-lab/keyward/internal/vault"
)

// flat is s with each run of white space as one space, so a test reads the words
// of a report whatever their columns and wrapping.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

// rows is each row of out with the lines under it, as flat makes them.
func rows(out string) []string {
	var got []string
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		end := i + 1
		for end < len(lines) && strings.HasPrefix(lines[end], "   ") {
			end++
		}
		got = append(got, flat(strings.Join(lines[i:end], "\n")))
	}
	return got
}

// row is the first row of out that holds start.
func row(out, start string) string {
	for _, r := range rows(out) {
		if strings.Contains(r+" ", start) {
			return r
		}
	}
	return ""
}

var headingLine = regexp.MustCompile("\n[✗!] ")

// section is the section of out whose heading starts with heading, up to the
// next heading, or empty if there is none.
func section(out, heading string) string {
	_, rest, ok := strings.Cut("\n"+out, "\n"+heading)
	if !ok {
		return ""
	}
	if at := headingLine.FindStringIndex(rest); at != nil {
		rest = rest[:at[0]+1]
	}
	return heading + rest
}

// column is where s starts in line, in runes, or -1.
func column(line, s string) int {
	i := strings.Index(line, s)
	if i < 0 {
		return -1
	}
	return utf8.RuneCountInString(line[:i])
}

// Each row of a list reads in columns: where, its tag, what holds it, and why it
// looks like a credential, which wraps in a column of its own. A name too long to
// leave that column room puts its reason under it, and no line is wider than the
// report.
func TestRowsAlignInColumnsWithinTheWidth(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".zshrc")
	long := strings.Repeat("VERY_LONG_", 6) + "TOKEN"
	const reason = "a reason long enough to wrap onto a second line and then a third one, in a column of its own, where it is read by whoever runs doctor"
	r := &doctor.Report{Scanned: []string{rc}, Plaintext: []doctor.Plaintext{
		{File: rc, Line: 7, Name: "BUILD_ID", Detection: migrate.Detection{Possible: true, Reason: reason}},
		{File: rc, Line: 12, Name: long, Detection: migrate.Detection{Possible: true, Reason: "a value named like a credential"}},
		{File: rc, Line: 130, Name: "API_KEY", Detection: migrate.Detection{Possible: true, Secret: true, Reason: "the variable name suggests a credential"}},
	}}

	out := r.Render(doctor.Format{Home: home})
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if n := utf8.RuneCountInString(line); n > 100 {
			t.Errorf("a line is %d columns wide:\n%s", n, line)
		}
	}
	at := func(prefix string) int {
		for i, line := range lines {
			if strings.HasPrefix(line, prefix) {
				return i
			}
		}
		t.Fatalf("no line starts %q:\n%s", prefix, out)
		return 0
	}
	first, named, moved := at("  ~/.zshrc:7 "), at("  ~/.zshrc:12 "), at("  ~/.zshrc:130 ")
	tag, why := column(lines[first], "add"), column(lines[first], "a reason")
	if column(lines[named], "add") != tag || column(lines[moved], "migrate") != tag {
		t.Errorf("the tags are not in one column:\n%s", out)
	}
	if column(lines[moved], "the variable") != why || why != column(lines[first], "BUILD_ID")+len("BUILD_ID")+2 {
		t.Errorf("the reasons are not in one column, after the widest name that leaves them room:\n%s", out)
	}
	if lines[first+1][:why] != strings.Repeat(" ", why) || lines[first+1][why] == ' ' || lines[first+2][:why] != strings.Repeat(" ", why) {
		t.Errorf("the reason does not wrap in its column:\n%s", out)
	}
	if !strings.HasSuffix(lines[named], long) || column(lines[named+1], "a value named") != why || strings.TrimSpace(lines[named+1]) != "a value named like a credential" {
		t.Errorf("a name too long for its column does not put its reason under it:\n%s", out)
	}
	if got := row(out, "~/.zshrc:7 "); got != "~/.zshrc:7 add BUILD_ID "+reason {
		t.Errorf("the first row reads %q", got)
	}
}

// Names long enough that a row would run past the width put what does not fit
// beside them under their row, a line each, so no line is wider than the report.
func TestALongNamePutsWhatDoesNotFitUnderItsRow(t *testing.T) {
	home := t.TempDir()
	rc, codex := filepath.Join(home, ".zshrc"), filepath.Join(home, ".codex/config.toml")
	orphan, unknown := "otel-exporter-otlp-traces-headers-staging-eu", strings.Repeat("a-very-long-name-", 4)
	r := &doctor.Report{
		Dangling: []doctor.Reference{{Name: "github-personal-access-token-staging", File: codex, Line: 3}, {Name: "github-personal-access-token", File: rc, Line: 2}},
		Orphaned: []doctor.Finding{
			{Entry: vault.Entry{Name: "old"}, Detail: "came from " + rc + ":9, which no longer references it"},
			{Entry: vault.Entry{Name: orphan}, Detail: "came from " + filepath.Join(home, ".config/app/credentials.env") + ":3, which no longer references it"},
		},
		Unknown: []doctor.Finding{{Entry: vault.Entry{Name: unknown}, Detail: "no record of where it came from, so it was probably added by hand"}},
	}

	beside := strings.Repeat(" ", 2+len(orphan)+2)
	want := "✗ 2 reference(s) point at secrets that are not in the vault\n" +
		"  ~/.codex/config.toml:3  cap://github-personal-access-token-staging\n" +
		"    keyward add github-personal-access-token-staging\n" +
		"  ~/.zshrc:2              cap://github-personal-access-token\n" +
		"    keyward add github-personal-access-token\n" +
		"\n" +
		"! 2 secret(s) whose source no longer references them\n" +
		"  old" + beside[len("  old"):] + "came from ~/.zshrc:9, which no longer references it\n" +
		"    keyward rm old\n" +
		"  " + orphan + "  came from ~/.config/app/credentials.env:3, which no\n" +
		beside + "longer references it\n" +
		"    keyward rm " + orphan + "\n" +
		"\n" +
		"! 1 secret(s) nothing scanned refers to, which may still be in use\n" +
		"  " + unknown + "\n" +
		"    no record of where it came from, so it was probably added by hand\n"
	got := r.Render(doctor.Format{Home: home})
	if got != want {
		t.Errorf("Render =\n%s\nwant\n%s", got, want)
	}
	for _, line := range strings.Split(got, "\n") {
		if n := utf8.RuneCountInString(line); n > 100 {
			t.Errorf("a line is %d columns wide:\n%s", n, line)
		}
	}
}

// An MCP server's fix differs from server to server, so it follows its row, under
// what holds the credential, where the row names the server's project. Nothing
// sits beside what a server's row names, so it does not push the values' reasons
// right.
func TestAnMCPServersFixIsUnderItsRow(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "app")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(home, ".zshrc")
	r := &doctor.Report{Scanned: []string{rc},
		Plaintext: []doctor.Plaintext{{File: rc, Line: 4, Name: "BUILD_ID", Detection: migrate.Detection{Possible: true, Reason: "a random 36-character token"}}},
		Literals: []mcpconfig.Literal{
			{Client: "Claude Code", Config: filepath.Join(home, ".claude.json") + " (project " + project + ")", Server: "github", Project: project,
				Field: "env.GITHUB_TOKEN", Detection: migrate.Detection{Possible: true, Reason: "a value named like a credential"}},
			{Client: "Claude Code", Config: filepath.Join(home, ".claude.json"), Server: "linear", Field: "env.LINEAR_API_KEY",
				Detection: migrate.Detection{Possible: true, Reason: "a value named like a credential"}},
		},
	}

	out := r.Render(doctor.Format{Home: home})
	want := "  ~/.zshrc:4      add  BUILD_ID  a random 36-character token\n" +
		"  ~/.claude.json  mcp  Claude Code server github, env.GITHUB_TOKEN (project ~/app)\n" +
		"                       a value named like a credential\n" +
		"                       if it is one, store it with keyward add NAME, write ${GITHUB_TOKEN} in its\n" +
		"                       place, add export GITHUB_TOKEN='cap://NAME' to ~/.zshrc, and run keyward mcp\n" +
		"                       wrap in ~/app\n" +
		"  ~/.claude.json  mcp  Claude Code server linear, env.LINEAR_API_KEY\n" +
		"                       a value named like a credential\n" +
		"                       if it is one, store it with keyward add NAME, write ${LINEAR_API_KEY} in its\n" +
		"                       place, add export LINEAR_API_KEY='cap://NAME' to ~/.zshrc, and run keyward\n" +
		"                       mcp wrap\n\n"
	if !strings.Contains(out, want) {
		t.Errorf("the report lacks\n%s\nin\n%s", want, out)
	}
}

// A location too long to leave a row room beside it has a line of its own, and
// the rest of its row follows on the next, in the columns the other rows use, so
// no line runs past the width and a short location's row reads as it would alone.
func TestALongLocationHasALineOfItsOwn(t *testing.T) {
	const home, project = "/Users/a", "/Volumes/work/client-projects/a-project-with-a-long-name"
	const reason = "a reason long enough to wrap in the columns a long location leaves it"
	possible := migrate.Detection{Possible: true, Reason: reason}
	r := &doctor.Report{Scanned: []string{home + "/.zshrc", project + "/.env"},
		Plaintext: []doctor.Plaintext{{File: home + "/.zshrc", Line: 2, Name: "BUILD_ID", Detection: possible}, {File: project + "/.env", Line: 3, Name: "BUILD_REF", Detection: possible}},
		Literals:  []mcpconfig.Literal{{Client: "Cursor", Config: project + "/.cursor/mcp.json", Server: "linear", Field: "env.LINEAR_API_KEY", Detection: possible}},
	}

	under, fix := strings.Repeat(" ", 14), strings.Repeat(" ", 19)
	want := "! 3 value(s) that may be credentials\n" +
		"  ~/.zshrc:2  add  BUILD_ID   " + reason + "\n" +
		"  " + project + "/.env:3\n" +
		under + "add  BUILD_REF  " + reason + "\n" +
		"  " + project + "/.cursor/mcp.json\n" +
		under + "mcp  Cursor server linear, env.LINEAR_API_KEY\n" +
		fix + reason + "\n" +
		fix + "if it is one, store it with keyward add NAME, write ${env:LINEAR_API_KEY} in its\n" +
		fix + "place, add export LINEAR_API_KEY='cap://NAME' to ~/.zshrc, and run keyward mcp\n" +
		fix + "wrap\n\n"
	out := r.Render(doctor.Format{Home: home})
	if !strings.HasPrefix(out, want) {
		t.Errorf("Render =\n%s\nwant it to start\n%s", out, want)
	}
	for _, line := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(line); n > 100 {
			t.Errorf("a line is %d columns wide:\n%s", n, line)
		}
	}
	if out := r.Render(tagged(home)); !strings.Contains(out, "\n  <c>"+project+"/.env:3</>\n") {
		t.Errorf("a location on a line of its own is not painted as one:\n%s", out)
	}
}

// Rows of each section read in file order, the files in the order they were read,
// and a value before the comment beside it; MCP servers come after every line. A
// file the report does not list as read comes after those it does, by name.
func TestRowsReadInFileOrder(t *testing.T) {
	home := t.TempDir()
	rc := write(t, home, ".zshrc", "# "+hex32+"\n\n\n\nexport BUILD_ID="+mixedToken+" # was "+hex32+"\n\n\n\n# "+githubToken+"\n\n\n\nexport GITHUB_TOKEN="+githubToken+"\n")
	env := write(t, home, ".zshenv", "export BUILD_REF="+mixedToken+"\n")
	servers := []mcpconfig.Server{{Client: "Claude Code", Config: filepath.Join(home, ".claude.json"), Name: "team", Command: "team-mcp", Env: map[string]string{"API_KEY": namedValue}}}

	r, err := doctor.Run(vault.NewMemory(), []string{rc, env}, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{Home: home})
	var got []string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); strings.HasPrefix(line, "  ~/") && len(fields) > 2 {
			got = append(got, fields[0]+" "+fields[2])
		}
	}
	want := "~/.zshrc:9 comment,~/.zshrc:13 GITHUB_TOKEN," +
		"~/.zshrc:1 comment,~/.zshrc:5 BUILD_ID,~/.zshrc:5 trailer,~/.zshenv:1 BUILD_REF,~/.claude.json Claude"
	if strings.Join(got, ",") != want {
		t.Errorf("rows %v, want %s:\n%s", got, want, out)
	}

	value := func(file string, line int) doctor.Plaintext {
		return doctor.Plaintext{File: file, Line: line, Name: "BUILD_ID", Detection: migrate.Detection{Possible: true, Reason: "a random 36-character token"}}
	}
	r = &doctor.Report{Scanned: []string{"/z"}, Plaintext: []doctor.Plaintext{value("/c", 1), value("/b", 2), value("/z", 3), value("/b", 1)}}
	got = nil
	for _, line := range strings.Split(r.Render(doctor.Format{}), "\n") {
		if strings.HasPrefix(line, "  /") {
			got = append(got, strings.Fields(line)[0])
		}
	}
	if want := "/z:3,/b:1,/b:2,/c:1"; strings.Join(got, ",") != want {
		t.Errorf("rows %v, want %s", got, want)
	}
}

// A section's legend says how to fix each tag it uses, and only those.
func TestALegendListsOnlyTheTagsItsSectionUses(t *testing.T) {
	home := t.TempDir()
	rc := write(t, home, ".zshrc", "export GITHUB_TOKEN="+githubToken+"\n\n\n\nexport BUILD_ID="+mixedToken+"\n\n\n\n# "+hex32+"\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{Home: home})
	certain, possible := section(out, "✗ 1 credential(s) in plaintext"), section(out, "! 2 value(s) that may be credentials")
	if !strings.Contains(certain, "\n    migrate  ") || strings.Contains(certain, "\n    add ") || strings.Contains(certain, "\n    edit ") {
		t.Errorf("the legend for the credentials does not list migrate alone:\n%s", certain)
	}
	if strings.Contains(possible, "\n    migrate ") || !strings.Contains(possible, "\n    add   ") || !strings.Contains(possible, "\n    edit  ") {
		t.Errorf("the legend for the values does not list add and edit alone:\n%s", possible)
	}
	if want := "✗ 1 credential(s) in plaintext\n" +
		"  ~/.zshrc:1  migrate  GITHUB_TOKEN  a GitHub token\n" +
		"\n" +
		"  To fix each:\n" +
		"    migrate  move it with keyward migrate ~/.zshrc (preview with --dry-run), or store it with\n" +
		"             keyward add NAME and set the variable to 'cap://NAME'\n" +
		"    e.g. keyward add github-token and set GITHUB_TOKEN to 'cap://github-token'\n" +
		"  Then rotate each one, and store its new value with keyward add --force NAME.\n" +
		"  AI agents must not open these lines or print these configs; ask the user to fix them.\n\n"; certain != want {
		t.Errorf("the credentials read\n%s\nwant\n%s", certain, want)
	}
	if want := "If one is a credential: add store it with keyward add NAME and set the variable to 'cap://NAME'; migrate moves only values it is sure of " +
		"edit remove it by hand in an editor e.g. keyward add build-id and set BUILD_ID to 'cap://build-id' Rotate each one"; !strings.Contains(flat(possible), want) {
		t.Errorf("the values lack %q:\n%s", want, possible)
	}
}

// migrate names the file to move a value out of, when every row it would move
// shares one; otherwise the legend says to run it on each row's file.
func TestTheLegendNamesTheFileToMigrateWhenThereIsOne(t *testing.T) {
	home := t.TempDir()
	rc := write(t, home, ".zshrc", "export GITHUB_TOKEN="+githubToken+"\n")
	env := write(t, home, ".env", "GITLAB_TOKEN=glpat-"+"FakeLegendGitLab0000\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc, env}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := "migrate move it with keyward migrate on the file it is in (preview with --dry-run), or store it"; !strings.Contains(flat(r.Render(doctor.Format{Home: home})), want) {
		t.Errorf("the report lacks %q:\n%s", want, r.Render(doctor.Format{Home: home}))
	}
}

// The legend gives an example of the first value of its section whose name can
// become a reference's, and none where no value's can.
func TestTheExampleIsTheFirstValueThatCanBeAReference(t *testing.T) {
	const rc = "/home/someone/.zshrc"
	possible := func(line int, name string) doctor.Plaintext {
		return doctor.Plaintext{File: rc, Line: line, Name: name, Detection: migrate.Detection{Possible: true, Reason: "a value named like a credential"}}
	}
	comment := doctor.Unmovable{File: rc, UnmovableLine: migrate.UnmovableLine{Line: 9, Kind: "comment", Labels: []migrate.Label{{One: "32 hex characters", Many: "runs of 32 hex characters"}}}}
	for _, tc := range []struct {
		name      string
		plaintext []doctor.Plaintext
		unmovable []doctor.Unmovable
		want      string
	}{
		{"the first value", []doctor.Plaintext{possible(1, "BUILD_ID"), possible(2, "BUILD_REF")}, nil, "e.g. keyward add build-id and set BUILD_ID to 'cap://build-id'"},
		{"the first that can be one", []doctor.Plaintext{possible(1, "_TOKEN"), possible(2, "BUILD_REF")}, nil, "e.g. keyward add build-ref and set BUILD_REF to 'cap://build-ref'"},
		{"no value that can be one", []doctor.Plaintext{possible(1, "_TOKEN")}, nil, ""},
		{"no value", nil, []doctor.Unmovable{comment}, ""},
	} {
		r := &doctor.Report{Scanned: []string{rc}, Plaintext: tc.plaintext, Unmovable: tc.unmovable}
		out := r.Render(doctor.Format{})
		if got := strings.Count(out, "e.g."); tc.want == "" && got != 0 || tc.want != "" && (got != 1 || !strings.Contains(out, "\n    "+tc.want+"\n")) {
			t.Errorf("%s: want %q:\n%s", tc.name, tc.want, out)
		}
		if strings.Contains(out, " \n") {
			t.Errorf("%s: a line ends in a space:\n%s", tc.name, out)
		}
	}
}

const listedTwice = "Marking leaves the whole line alone, so mark a line listed twice, for its value and for the comment beside it, only once neither holds a secret."

// Marking a line marks its value and the comment beside it alike, so the values
// that may be credentials say so where their section lists a value whose comment
// is listed too, or such a comment, in either section, and only then.
func TestTheValuesSayALineListedTwiceIsMarkedOnlyOnceNeitherHoldsASecret(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		want       bool
	}{
		{"both may be credentials", "export BUILD_ID=" + mixedToken + " # was " + hex32, true},
		{"the value is a credential", "export GITHUB_TOKEN=" + githubToken + " # was " + hex32, true},
		{"the comment is a credential", "export BUILD_ID=" + mixedToken + " # was " + githubToken, true},
		{"both are credentials", "export GITHUB_TOKEN=" + githubToken + " # was " + githubToken, false},
		{"the comment beside a reference", "export A='cap://alpha' # was " + hex32, false},
		{"the value alone", "export BUILD_ID=" + mixedToken, false},
	} {
		home := t.TempDir()
		rc := write(t, home, ".zshrc", tc.line+"\n")
		r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc}, nil)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := r.Render(doctor.Format{Home: home})
		if got := strings.Count(flat(out), listedTwice); got != map[bool]int{true: 1}[tc.want] {
			t.Errorf("%s: the report says a line listed twice is marked once neither holds a secret %d times:\n%s", tc.name, got, out)
		}
		if strings.Contains(section(out, "✗ "), "Marking") {
			t.Errorf("%s: the credentials speak of marking:\n%s", tc.name, out)
		}
	}
}

// Only a line of a shell or .env file can be marked as holding no secret, so the
// values that may be credentials say how only where one of them is such a line.
func TestTheIgnoreSentenceAppearsOnlyWhereALineCanBeMarked(t *testing.T) {
	home := t.TempDir()
	rc := write(t, home, ".zshrc", "export BUILD_ID="+mixedToken+"\n")
	servers := []mcpconfig.Server{{Client: "Claude Code", Config: filepath.Join(home, ".claude.json"), Name: "team", Command: "team-mcp", Env: map[string]string{"API_KEY": namedValue}}}
	const ignore = "If one holds no secret, end its line with # keyward:ignore yourself, and keyward leaves the line alone (shell and .env files only); an AI agent must not."

	for _, tc := range []struct {
		name    string
		paths   []string
		servers []mcpconfig.Server
		want    int
	}{
		{"a line", []string{rc}, nil, 1},
		{"an MCP server alone", nil, servers, 0},
	} {
		r, err := doctor.Run(vault.NewMemory(), tc.paths, tc.servers)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := r.Render(doctor.Format{Home: home})
		if got := strings.Count(flat(out), ignore); got != tc.want {
			t.Errorf("%s: the report says how to mark a line %d times, want %d:\n%s", tc.name, got, tc.want, out)
		}
	}
}

// Paths under home read as ~/, as the rest of keyward shows them, and only those:
// a folder whose name only starts with home's is another folder, and so is one
// whose path holds home's further in, as an old disk's.
func TestPathsUnderHomeReadAsTilde(t *testing.T) {
	home := t.TempDir()
	other, mounted := home+"b", filepath.Join("/Volumes/Old Mac"+home, ".zshrc")
	project, gone := filepath.Join(home, "app"), filepath.Join(home, "removed")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	rc, elsewhere, claude := filepath.Join(home, ".zshrc"), filepath.Join(other, ".zshrc"), filepath.Join(home, ".claude.json")
	literal := func(dir string) mcpconfig.Literal {
		return mcpconfig.Literal{Client: "Claude Code", Config: claude + " (project " + dir + ")", Server: filepath.Base(dir), Project: dir, Field: "env.GITHUB_TOKEN",
			Detection: migrate.Detection{KnownShape: true, Secret: true, Reason: "a GitHub token"}}
	}
	r := &doctor.Report{
		Scanned:   []string{rc, elsewhere, mounted},
		Absent:    []string{filepath.Join(home, ".zlogin")},
		Dangling:  []doctor.Reference{{Name: "absent", File: rc, Line: 1}, {Name: "absent", File: elsewhere, Line: 2}, {Name: "absent", File: mounted, Line: 4}},
		Plaintext: []doctor.Plaintext{{File: rc, Line: 3, Name: "GITHUB_TOKEN", Detection: migrate.Detection{Secret: true, KnownShape: true, Reason: "a GitHub token"}}},
		Literals:  []mcpconfig.Literal{literal(project), literal(gone)},
		Orphaned: []doctor.Finding{
			{Entry: vault.Entry{Name: "old"}, Detail: "came from " + rc + ":9, which no longer references it"},
			{Entry: vault.Entry{Name: "older"}, Detail: "came from " + mounted + ":5, which no longer references it"},
		},
		Unknown: []doctor.Finding{{Entry: vault.Entry{Name: "app-key"}, Detail: "came from " + filepath.Join(home, ".config/app/.env") + ", which no longer exists"}},
	}

	f := doctor.Format{Home: home}
	out := r.Render(f) + r.Summary(f, nil, nil)
	for _, want := range []string{
		"~/.zshrc:1 cap://absent keyward add absent",
		elsewhere + ":2 cap://absent keyward add absent",
		mounted + ":4 cap://absent keyward add absent",
		"migrate move it with keyward migrate ~/.zshrc (preview",
		"~/.claude.json mcp Claude Code server app, env.GITHUB_TOKEN (project ~/app)",
		"and run keyward mcp wrap in ~/app ",
		"remove the server from ~/.claude.json by hand, with Claude Code closed, as its project's folder no longer exists",
		"old came from ~/.zshrc:9, which no longer references it keyward rm old",
		"Mac" + home + "/.zshrc:5, which no longer references it",
		"app-key came from ~/.config/app/.env, which no longer exists",
		"keyward doctor read ~/.zshrc, " + elsewhere + ", " + mounted + " not read ~/.zlogin",
	} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, home+"/") != strings.Count(out, "Mac"+home+"/") || strings.Contains(out, "~b") {
		t.Errorf("the report shows home other than as ~/:\n%s", out)
	}
}

// Each check of the report has a line of its own, saying it passed where it did.
func TestTheReportsChecks(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "A=cap://alpha\n")
	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []doctor.Check{
		{Status: doctor.Pass, Label: "References", Text: "1 secret(s) stored and referenced"},
		{Status: doctor.Pass, Label: "Known secrets", Text: "none in plaintext"},
		{Status: doctor.Pass, Label: "Maybe secrets", Text: "nothing else looks like one"},
		{Status: doctor.Pass, Label: "Unused", Text: "none"},
	}
	if got := r.Checks(); !slices.Equal(got, want) {
		t.Errorf("Checks() = %+v, want %+v", got, want)
	}

	rc = write(t, dir, ".zshrc", "A=cap://absent\nB=cap://-malformed\nC=cap://present\nD="+githubToken+"\nGIT_AUTHOR_EMAIL=someone@example.com\n")
	r, err = doctor.Run(store(t, map[string]string{"present": rc + ":3", "orphan": rc + ":9", "by-hand": ""}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want = []doctor.Check{
		{Status: doctor.Fail, Label: "References", Text: "1 secret(s) stored and referenced; 1 reference(s) to secrets that are not in the vault; 1 malformed reference(s), listed above"},
		{Status: doctor.Fail, Label: "Known secrets", Text: "1 credential(s) in plaintext, listed above"},
		{Status: doctor.Attention, Label: "Maybe secrets", Text: "1 value(s) that may be credentials, listed above"},
		{Status: doctor.Attention, Label: "Unused", Text: "1 secret(s) whose source no longer references them; 1 secret(s) nothing scanned refers to, listed above"},
	}
	if got := r.Checks(); !slices.Equal(got, want) {
		t.Errorf("Checks() = %+v, want %+v", got, want)
	}
}

// The summary ends a report: its notes but empty ones, what was read, and a line
// for each check, in columns, a label left blank where it repeats the one above.
func TestTheSummaryListsWhatWasReadAndEachCheck(t *testing.T) {
	home := t.TempDir()
	var scanned []string
	for _, name := range []string{".zshrc", ".zshenv", ".zprofile", ".claude.json", ".bash_profile", ".config/some/long/path/for/wrapping.env"} {
		scanned = append(scanned, filepath.Join(home, name))
	}
	r := &doctor.Report{Scanned: scanned, Referenced: []string{"alpha", "beta"}}
	more := []doctor.Check{
		{Status: doctor.Fail, Label: "MCP servers", Text: "1 MCP server(s) would receive cap:// references instead of values; see keyward mcp"},
		{Status: doctor.Attention, Label: "MCP servers", Text: "1 MCP server(s) start unchecked, as allowed with --allow-command-line; see keyward mcp"},
	}

	got := r.Summary(doctor.Format{Home: home}, append(r.Checks(), more...), []string{"", "keyward reads a note long enough to wrap at the width of the report, which it does at one hundred columns, here."})
	want := "Note: keyward reads a note long enough to wrap at the width of the report, which it does at one\n" +
		"hundred columns, here.\n" +
		"\n" +
		"keyward doctor  read ~/.zshrc, ~/.zshenv, ~/.zprofile, ~/.claude.json, ~/.bash_profile,\n" +
		"                     ~/.config/some/long/path/for/wrapping.env\n" +
		"  ✓ References     2 secret(s) stored and referenced\n" +
		"  ✓ Known secrets  none in plaintext\n" +
		"  ✓ Maybe secrets  nothing else looks like one\n" +
		"  ✓ Unused         none\n" +
		"  ✗ MCP servers    1 MCP server(s) would receive cap:// references instead of values; see keyward\n" +
		"                   mcp\n" +
		"  !                1 MCP server(s) start unchecked, as allowed with --allow-command-line; see\n" +
		"                   keyward mcp\n"
	if got != want {
		t.Errorf("Summary =\n%s\nwant\n%s", got, want)
	}

	r = &doctor.Report{Absent: []string{filepath.Join(home, ".zlogin"), filepath.Join(home, ".profile")}}
	if got := r.Summary(doctor.Format{Home: home}, r.Checks(), nil); !strings.HasPrefix(got, "keyward doctor  read no files\n                not read ~/.zlogin, ~/.profile\n  ✓ ") {
		t.Errorf("Summary =\n%s", got)
	}
}

// The verdict sums up every check: the problems found, wrapped within the width,
// or that there are none, and how many checks need attention.
func TestTheVerdictCountsTheChecksThatNeedAttention(t *testing.T) {
	pass := doctor.Check{Status: doctor.Pass, Label: "Backups", Text: "none from migrate"}
	attention := doctor.Check{Status: doctor.Attention, Label: "Backups", Text: "1 backup(s) from migrate still hold old values; review them with keyward backups"}
	for _, tc := range []struct {
		name     string
		checks   []doctor.Check
		problems []string
		want     string
	}{
		{"clean", []doctor.Check{pass}, nil, "✓ No problems found.\n"},
		{"one check", []doctor.Check{pass, attention}, nil, "✓ No problems found. 1 check needs attention.\n"},
		{"three checks", []doctor.Check{attention, pass, attention, attention}, nil, "✓ No problems found. 3 checks need attention.\n"},
		{"problems", []doctor.Check{attention}, []string{"1 credential(s) in plaintext", "the vault does not open"},
			"✗ Problems found: 1 credential(s) in plaintext; the vault does not open.\n"},
		{"problems up to the width", nil, []string{"the vault does not open", "1 MCP server(s) would receive cap:// references instead of values"},
			"✗ Problems found: the vault does not open; 1 MCP server(s) would receive cap:// references instead\n  of values.\n"},
	} {
		if got := (doctor.Format{}).Verdict(tc.checks, tc.problems); got != tc.want {
			t.Errorf("%s: Verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// tagged paints each part as <s>text</>, where s is b for a heading, g, y and r
// for the icons, c for a command and d for quiet text.
func tagged(home string) doctor.Format {
	names := map[doctor.Style]string{doctor.Heading: "b", doctor.OK: "g", doctor.Warning: "y", doctor.Problem: "r", doctor.Command: "c", doctor.Quiet: "d"}
	return doctor.Format{Home: home, Paint: func(s doctor.Style, text string) string { return "<" + names[s] + ">" + text + "</>" }}
}

// Painted, each part of the report is styled for what it is, and the columns
// still align, as only the plain text is measured.
func TestPaintStylesEachPartWithoutMovingAColumn(t *testing.T) {
	home := t.TempDir()
	long, name := strings.Repeat("long-reference-name-", 2)+"x", strings.Repeat("VERY_LONG_", 6)+"TOKEN"
	rc := write(t, home, ".zshrc", "export GITHUB_TOKEN="+githubToken+"\nexport T='cap://absent'\nexport BUILD_ID="+mixedToken+"\n"+
		strings.Repeat("\n", 8)+"export MY_SERVICE_TOKEN="+namedValue+"\nexport L='cap://"+long+"'\nexport "+name+"="+namedValue+"\n")
	paths := []string{rc}
	for _, c := range "ab" {
		paths = append(paths, filepath.Join(home, ".config", "absent-file-with-a-long-name-"+string(c)+".env"))
	}
	servers := []mcpconfig.Server{{Client: "Claude Code", Config: filepath.Join(home, ".claude.json"), Name: "github", Command: "gh-mcp", Env: map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": githubToken}}}
	r, err := doctor.Run(store(t, map[string]string{"orphan-of-a-removed-line": rc + ":9", "by-hand": ""}), paths, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	checks := append(r.Checks(), doctor.Check{Status: doctor.Pass, Label: "Backups", Text: "none from migrate"})
	f := tagged(home)
	out := r.Render(f) + r.Summary(f, checks, []string{"a note"}) + "\n" + f.Verdict(checks, r.Problems())
	under := func(n int) string { return strings.Repeat(" ", n) }
	for _, want := range []string{
		"<r>✗</> <b>2 reference(s) point at secrets that are not in the vault</>\n  <c>~/.zshrc:2</>   cap://absent\n    <c>keyward add absent</>\n",
		"  <c>~/.zshrc:1</>      <c>migrate</>  GITHUB_TOKEN  <d>a GitHub token</>\n",
		"  <c>~/.claude.json</>  <c>mcp</>      Claude Code server github, env.GITHUB_PERSONAL_ACCESS_TOKEN\n" +
			under(27) + "<d>a GitHub token</>\n" + under(27) + "store it with keyward add NAME,",
		"    <c>migrate</>  move it with keyward migrate ~/.zshrc",
		"  <y>AI agents must not open these lines or print these configs; ask the user to fix them.</>\n",
		"<y>!</> <b>3 value(s) that may be credentials</>\n" +
			"  <c>~/.zshrc:3</>   <c>add</>      BUILD_ID          <d>a random 36-character token</>\n" +
			"  <c>~/.zshrc:12</>  <c>migrate</>  MY_SERVICE_TOKEN  <d>the variable name suggests a credential</>\n" +
			"  <c>~/.zshrc:14</>  <c>migrate</>  " + name + "\n" + under(42) + "<d>the variable name suggests a credential</>\n",
		"  <y>AI agents must not open these lines or print these configs; ask the user to judge them.</>\n",
		"    <d>e.g. keyward add build-id and set BUILD_ID to 'cap://build-id'</>\n",
		"  orphan-of-a-removed-line  <d>came from ~/.zshrc:9, which no</>       <c>keyward rm orphan-of-a-removed-line</>\n" +
			under(28) + "<d>longer references it</>\n",
		"  by-hand  <d>no record of where it came from, so it was probably added by hand</>\n",
		"<d>Note: a note</>\n",
		"<b>keyward doctor</>  <d>read ~/.zshrc</>\n" + under(16) + "<d>not read ~/.config/absent-file-with-a-long-name-a.env,</>\n" +
			under(25) + "<d>~/.config/absent-file-with-a-long-name-b.env, ~/.claude.json</>\n",
		"  <g>✓</> Backups        none from migrate\n",
		"  <y>!</> Unused         1 secret(s)",
		"  <r>✗</> References     0 secret(s) stored",
		"<r><b>✗ Problems found: 2 reference(s) to secrets that are not in the vault; 2 credential(s) in plaintext.</></>\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if regexp.MustCompile(`<[a-z]></>`).MatchString(out) {
		t.Errorf("the report paints empty text:\n%s", out)
	}
	plain := regexp.MustCompile(`</?[a-z]?>`).ReplaceAllString(out, "")
	unpainted := r.Render(doctor.Format{Home: home}) + r.Summary(doctor.Format{Home: home}, checks, []string{"a note"}) + "\n" + doctor.Format{}.Verdict(checks, r.Problems())
	if plain != unpainted {
		t.Errorf("painting moved the text:\n%s\nwant\n%s", plain, unpainted)
	}
	for _, tc := range []struct {
		checks   []doctor.Check
		problems []string
		want     string
	}{
		{nil, nil, "<g><b>✓ No problems found.</></>\n"},
		{[]doctor.Check{{Status: doctor.Attention}}, nil, "<g><b>✓ No problems found.</></> <d>1 check needs attention.</>\n"},
		{nil, []string{"the vault does not open", "1 MCP server(s) would receive cap:// references instead of values"},
			"<r><b>✗ Problems found: the vault does not open; 1 MCP server(s) would receive cap:// references instead</></>\n  <r><b>of values.</></>\n"},
	} {
		if got := f.Verdict(tc.checks, tc.problems); got != tc.want {
			t.Errorf("Verdict = %q, want %q", got, tc.want)
		}
	}
}
