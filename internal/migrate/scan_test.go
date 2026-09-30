package migrate_test

import (
	"strings"
	"testing"

	"github.com/nwokolo24/keyward/internal/migrate"
)

// Round-trip fidelity is the property everything else depends on. This tool
// rewrites a file the user did not write for it, so any byte it changes without
// being asked is a bug — and one that shows up as a broken shell.
func TestScanRoundTripsExactly(t *testing.T) {
	inputs := []string{
		"",
		"\n",
		"\n\n\n",
		"export FOO=bar",
		"export FOO=bar\n",
		"export FOO=bar\nexport BAZ=qux\n",
		"# just a comment\n",
		"\r\n",
		"export FOO=bar\r\nexport BAZ=qux\r\n",
		"  indented=yes\n",
		"no trailing newline",
		"trailing whitespace   \n",
		"export A=1 B=2\n",
		"weird $( ) `` stuff\n",
		"\t\texport\tTABS=yes\n",
		"export EMPTY=\n",
		"mixed\nline\r\nendings\n",
	}
	for _, in := range inputs {
		f := migrate.Scan([]byte(in))
		if got := string(f.Bytes()); got != in {
			t.Errorf("Scan/Bytes round trip changed the file:\n  in  %q\n  out %q", in, got)
		}
	}
}

func TestScanFindsAssignments(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantN   string // variable name
		wantV   string // unquoted value
		wantPre string
		wantTrl string
	}{
		{"plain export", "export FOO=bar", "FOO", "bar", "export ", ""},
		{"no export", "FOO=bar", "FOO", "bar", "", ""},
		{"single quoted", "export FOO='bar baz'", "FOO", "bar baz", "export ", ""},
		{"double quoted", `export FOO="bar baz"`, "FOO", "bar baz", "export ", ""},
		{"empty value", "export FOO=", "FOO", "", "export ", ""},
		{"empty quoted", `export FOO=""`, "FOO", "", "export ", ""},
		{"indented", "  export FOO=bar", "FOO", "bar", "  export ", ""},
		{"tabs", "\texport\tFOO=bar", "FOO", "bar", "\texport\t", ""},
		{"extra spaces after export", "export   FOO=bar", "FOO", "bar", "export   ", ""},
		{"trailing comment", "export FOO=bar # why", "FOO", "bar", "export ", " # why"},
		{"comment after quotes", `export FOO="bar" # why`, "FOO", "bar", "export ", " # why"},
		{"carriage return", "export FOO=bar\r", "FOO", "bar", "export ", "\r"},
		{"hash inside quotes", `export FOO="a#b"`, "FOO", "a#b", "export ", ""},
		{"escaped quote", `export FOO="say \"hi\""`, "FOO", `say "hi"`, "export ", ""},
		{"underscores and digits", "export FOO_BAR2=v", "FOO_BAR2", "v", "export ", ""},
		{"leading underscore name", "export _FOO=v", "_FOO", "v", "export ", ""},
		{"value with equals", "export FOO=a=b", "FOO", "a=b", "export ", ""},
		{"dollar in value", `export FOO="$HOME/bin"`, "FOO", "$HOME/bin", "export ", ""},
		// The shell resolves \\ inside double quotes to one backslash.
		{"escaped backslash", `export FOO="a\\b"`, "FOO", `a\b`, "export ", ""},
		// \s is not an escape, so both characters stay as written.
		{"lone backslash kept", `export FOO="back\slash"`, "FOO", `back\slash`, "export ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := migrate.Scan([]byte(tt.line + "\n"))
			if len(f.Assignments) != 1 {
				t.Fatalf("found %d assignments in %q, want 1", len(f.Assignments), tt.line)
			}
			a := f.Assignments[0]
			if a.Name != tt.wantN {
				t.Errorf("Name = %q, want %q", a.Name, tt.wantN)
			}
			if a.Value != tt.wantV {
				t.Errorf("Value = %q, want %q", a.Value, tt.wantV)
			}
			if a.Prefix != tt.wantPre {
				t.Errorf("Prefix = %q, want %q", a.Prefix, tt.wantPre)
			}
			if a.Trailer != tt.wantTrl {
				t.Errorf("Trailer = %q, want %q", a.Trailer, tt.wantTrl)
			}
			if a.Line != 1 {
				t.Errorf("Line = %d, want 1", a.Line)
			}
			if a.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", a.Raw, tt.line)
			}
		})
	}
}

// Anything the scanner is not certain about must be left alone. A missed secret
// stays in plaintext, which is the status quo; a mangled line breaks the shell.
func TestScanSkipsWhatItCannotParse(t *testing.T) {
	skipped := []string{
		"# export FOO=bar",
		"#export FOO=bar",
		"export FOO",
		"export",
		"",
		"   ",
		"export 1FOO=bar",
		"export FOO-BAR=v",
		"export A=1 B=2",
		"export FOO=bar baz",
		`export FOO='unterminated`,
		`export FOO="unterminated`,
		// \" escapes the quote, so this value is unterminated too.
		`export FOO="end\"`,
		// A trailing backslash has nothing to escape and leaves the quote open.
		`export FOO="end\`,
		`export FOO='it'"'"'s'`,
		"alias ll='ls -l'",
		"if [ -n \"$FOO\" ]; then",
		"echo FOO=bar",
		"local FOO=bar",
		"FOO+=bar",
	}
	for _, line := range skipped {
		f := migrate.Scan([]byte(line + "\n"))
		if len(f.Assignments) != 0 {
			t.Errorf("Scan(%q) found %d assignments, want 0: %+v", line, len(f.Assignments), f.Assignments)
		}
	}
}

func TestScanRecordsLineNumbers(t *testing.T) {
	content := "# comment\nexport FIRST=1\n\nexport SECOND=2\n# another\nexport THIRD=3\n"
	f := migrate.Scan([]byte(content))

	if len(f.Assignments) != 3 {
		t.Fatalf("found %d assignments, want 3", len(f.Assignments))
	}
	want := []struct {
		line int
		name string
	}{{2, "FIRST"}, {4, "SECOND"}, {6, "THIRD"}}

	for i, w := range want {
		if got := f.Assignments[i]; got.Line != w.line || got.Name != w.name {
			t.Errorf("assignment %d = line %d %q, want line %d %q", i, got.Line, got.Name, w.line, w.name)
		}
	}
}

// Only an exported variable reaches the child processes keyward run starts. A bare
// `export NAME` anywhere in the file exports it too, in bash and zsh alike.
func TestScanRecordsExports(t *testing.T) {
	content := "export DIRECT=1\n" +
		"SHELL_ONLY=2\n" +
		"LATER=3\n" +
		"  export   LATER OTHER # both\n" +
		"export # nothing\n"
	f := migrate.Scan([]byte(content))

	for _, c := range []struct {
		name string
		want bool
	}{
		{"DIRECT", true},
		{"SHELL_ONLY", false},
		{"LATER", true},
		{"OTHER", true},
		{"NEVER_MENTIONED", false},
	} {
		if got := f.Exported(c.name); got != c.want {
			t.Errorf("Exported(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// Replace is how a plan is applied. Only the named line may change.
func TestReplaceChangesOnlyOneLine(t *testing.T) {
	content := "export FIRST=1\nexport SECOND=2\nexport THIRD=3\n"
	f := migrate.Scan([]byte(content))

	f.Replace(2, "export SECOND='cap://second'")

	want := "export FIRST=1\nexport SECOND='cap://second'\nexport THIRD=3\n"
	if got := string(f.Bytes()); got != want {
		t.Errorf("Bytes() =\n%q\nwant\n%q", got, want)
	}
}

func TestReplacePreservesMissingFinalNewline(t *testing.T) {
	f := migrate.Scan([]byte("export FOO=bar"))
	f.Replace(1, "export FOO='cap://foo'")

	if got, want := string(f.Bytes()), "export FOO='cap://foo'"; got != want {
		t.Errorf("Bytes() = %q, want %q with no newline added", got, want)
	}
}

// A line number outside the file is a programming error, and silently doing
// nothing would make a plan appear to succeed while changing nothing.
func TestReplaceOutOfRangePanics(t *testing.T) {
	f := migrate.Scan([]byte("export FOO=bar\n"))
	for _, n := range []int{0, 2, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Replace(%d, ...) did not panic", n)
				}
			}()
			f.Replace(n, "x")
		}()
	}
}

// A realistic rc file: the scanner must find the credentials and ignore the rest.
func TestScanRealisticRcFile(t *testing.T) {
	content := `# ~/.zshrc

export EDITOR=vim
export PATH="$HOME/.local/bin:$PATH"
export LANG=en_US.UTF-8

# work
export AWS_PROFILE=dashweb
export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsi
export ATLASSIAN_MCP_AUTH="Basic bm53b2tvbG8="
export GITHUB_TOKEN='ghp_exampleTokenValue'

alias gs='git status'
[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh
`
	f := migrate.Scan([]byte(content))

	var names []string
	for _, a := range f.Assignments {
		names = append(names, a.Name)
	}
	want := []string{
		"EDITOR", "PATH", "LANG", "AWS_PROFILE",
		"SPLUNK_MCP_TOKEN", "ATLASSIAN_MCP_AUTH", "GITHUB_TOKEN",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("assignments = %v, want %v", names, want)
	}
	if got := string(f.Bytes()); got != content {
		t.Error("round trip changed a realistic rc file")
	}
}

// Rewritten produces the line that will actually be written into the user's file,
// so every part of the original except the value has to survive it.
func TestRewritten(t *testing.T) {
	tests := []struct {
		name string
		line string
		ref  string
		want string
	}{
		{"plain", "export FOO=bar", "foo", "export FOO='cap://foo'"},
		{"no export", "FOO=bar", "foo", "FOO='cap://foo'"},
		{"indented", "  export FOO=bar", "foo", "  export FOO='cap://foo'"},
		{"tabs", "\texport\tFOO=bar", "foo", "\texport\tFOO='cap://foo'"},
		{"extra spaces", "export   FOO=bar", "foo", "export   FOO='cap://foo'"},
		{"trailing comment", "export FOO=bar # why", "foo", "export FOO='cap://foo' # why"},
		{"carriage return", "export FOO=bar\r", "foo", "export FOO='cap://foo'\r"},

		// Quoting is normalised to single quotes whatever the original was. Single
		// quotes suppress every form of shell expansion, so the reference reaches
		// keyward exactly as written.
		{"was double quoted", `export FOO="bar baz"`, "foo", "export FOO='cap://foo'"},
		{"was single quoted", "export FOO='bar'", "foo", "export FOO='cap://foo'"},
		{"was unquoted", "export FOO=bar", "foo", "export FOO='cap://foo'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := migrate.Scan([]byte(tt.line + "\n"))
			if len(f.Assignments) != 1 {
				t.Fatalf("found %d assignments in %q, want 1", len(f.Assignments), tt.line)
			}
			if got := f.Assignments[0].Rewritten(tt.ref); got != tt.want {
				t.Errorf("Rewritten(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

// A rewrite must land in the file exactly as Rewritten produced it.
func TestRewrittenAppliedToFile(t *testing.T) {
	content := "# rc\nexport EDITOR=vim\nexport GITHUB_TOKEN=ghp_secret # work\n"
	f := migrate.Scan([]byte(content))

	a := f.Assignments[1]
	f.Replace(a.Line, a.Rewritten("github-token"))

	want := "# rc\nexport EDITOR=vim\nexport GITHUB_TOKEN='cap://github-token' # work\n"
	if got := string(f.Bytes()); got != want {
		t.Errorf("Bytes() =\n%q\nwant\n%q", got, want)
	}
}
