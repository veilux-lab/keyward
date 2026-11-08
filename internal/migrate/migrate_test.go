package migrate_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/migrate"
	"github.com/veilux-lab/keyward/internal/vault"
)

const rcFile = `# ~/.zshrc

export EDITOR=vim
export PATH="$HOME/.local/bin:$PATH"

# work
export AWS_PROFILE=dashweb
export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9
export GITHUB_TOKEN='ghp_exampleTokenValue0123456789'

alias gs='git status'
`

// writeRC puts content in a temp file and returns its path.
func writeRC(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

func mustPlan(t *testing.T, path, content string) *migrate.Plan {
	t.Helper()
	p, err := migrate.NewPlan(path, []byte(content))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

// ===========================================================================
// Planning
// ===========================================================================

func TestNewPlanFindsSecretsAndLeavesTheRestAlone(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)

	var changed []string
	for _, c := range p.Changes {
		changed = append(changed, c.Name+"="+c.RefName)
	}
	want := []string{
		"SPLUNK_MCP_TOKEN=splunk-mcp-token",
		"GITHUB_TOKEN=github-token",
	}
	if strings.Join(changed, ",") != strings.Join(want, ",") {
		t.Errorf("Changes = %v, want %v", changed, want)
	}

	// Everything else must be accounted for, with a reason, so the plan can
	// explain itself rather than silently ignoring lines.
	var skipped []string
	for _, s := range p.Skips {
		if s.Reason == "" {
			t.Errorf("skip of %s has no reason", s.Name)
		}
		skipped = append(skipped, s.Name)
	}
	wantSkipped := []string{"EDITOR", "PATH", "AWS_PROFILE"}
	if strings.Join(skipped, ",") != strings.Join(wantSkipped, ",") {
		t.Errorf("Skips = %v, want %v", skipped, wantSkipped)
	}
}

func TestEmptyPlan(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", "export EDITOR=vim\n")
	if !p.Empty() {
		t.Error("Empty() = false, want true when there is nothing to move")
	}
}

// Two variables deriving the same reference name would collide on one vault
// entry, so the whole plan is refused rather than half applied.
func TestNewPlanRejectsCollidingRefNames(t *testing.T) {
	// The same variable assigned twice is the realistic way this happens — an rc
	// file that sets a token and later overrides it.
	content := "export MY_TOKEN=ghp_firstValue0123456789\nMY_TOKEN=ghp_secondValue0123456789\n"
	_, err := migrate.NewPlan("/tmp/.zshrc", []byte(content))
	if err == nil {
		t.Fatal("NewPlan accepted two assignments mapping to one reference name")
	}
	if !strings.Contains(err.Error(), "my-token") {
		t.Errorf("error = %v, want it to name the colliding reference", err)
	}
}

// A variable name that cannot become a valid reference is skipped, not fatal.
//
// Found by running against a real ~/.zshrc: one variable called oauth_client_id_
// blocked the entire file. A name that cannot be represented cannot collide with
// anything either, so leaving that one line in plaintext — the status quo — and
// migrating the rest is strictly better than migrating nothing.
func TestNewPlanSkipsUnusableNames(t *testing.T) {
	content := "export _TOKEN=ghp_unusableName0123456789\n" +
		"export oauth_client_id_=AbCdEfGhIjKlMnOpQrStUv\n" +
		"export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"

	p, err := migrate.NewPlan("/tmp/.zshrc", []byte(content))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	if len(p.Changes) != 1 || p.Changes[0].Name != "GITHUB_TOKEN" {
		t.Errorf("Changes = %+v, want only GITHUB_TOKEN", p.Changes)
	}

	skipped := map[string]string{}
	for _, s := range p.Skips {
		skipped[s.Name] = s.Reason
	}
	for _, name := range []string{"_TOKEN", "oauth_client_id_"} {
		reason, ok := skipped[name]
		if !ok {
			t.Errorf("%s was neither changed nor skipped", name)
			continue
		}
		// The reason has to be actionable: the user can rename the variable if
		// they want it migrated.
		if !strings.Contains(reason, "rename") {
			t.Errorf("skip reason for %s = %q, want it to suggest renaming", name, reason)
		}
	}
}

// A possible secret stays in the file, and the skip says how to move it by hand.
func TestNewPlanLeavesPossibleSecretsForTheUser(t *testing.T) {
	content := "export MY_THING=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i\n" +
		"export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"
	p := mustPlan(t, "/tmp/.zshrc", content)

	if len(p.Changes) != 1 || p.Changes[0].Name != "GITHUB_TOKEN" {
		t.Fatalf("Changes = %+v, want only GITHUB_TOKEN", p.Changes)
	}
	blocked := p.Blocked()
	if len(blocked) != 1 || blocked[0].Name != "MY_THING" {
		t.Fatalf("Blocked() = %+v, want MY_THING", blocked)
	}
	for _, want := range []string{"possibly a secret", "keyward add my-thing", "cap://my-thing"} {
		if !strings.Contains(blocked[0].Reason, want) {
			t.Errorf("reason = %q, want it to mention %q", blocked[0].Reason, want)
		}
	}
}

// A variable that is never exported only exists inside the shell, so keyward run
// can never resolve it. Rewriting it would leave the shell holding a reference
// nothing can turn back into the value. Found on a real ~/.zshrc.
func TestNewPlanLeavesUnexportedSecretsForTheUser(t *testing.T) {
	content := "SHELL_ONLY_TOKEN=ghp_shellOnlyValue0123456789\n" +
		"LATER_TOKEN=ghp_exportedLater0123456789\n" +
		"export LATER_TOKEN\n"
	p := mustPlan(t, "/tmp/.zshrc", content)

	if len(p.Changes) != 1 || p.Changes[0].Name != "LATER_TOKEN" {
		t.Fatalf("Changes = %+v, want only LATER_TOKEN", p.Changes)
	}
	blocked := p.Blocked()
	if len(blocked) != 1 || blocked[0].Name != "SHELL_ONLY_TOKEN" {
		t.Fatalf("Blocked() = %+v, want SHELL_ONLY_TOKEN", blocked)
	}
	for _, want := range []string{"not exported", "keyward run", "export"} {
		if !strings.Contains(blocked[0].Reason, want) {
			t.Errorf("reason = %q, want it to mention %q", blocked[0].Reason, want)
		}
	}
}

// A line whose comment holds keyward:ignore stays as written, whatever Detect makes
// of it, and needs no attention. doctor suggests the marker for GIT_AUTHOR_EMAIL;
// moved, it would give git a reference as the author's email.
func TestNewPlanLeavesMarkedLinesAlone(t *testing.T) {
	content := "export GIT_AUTHOR_EMAIL=someone@example.com # keyward:ignore\n" +
		"export BUILD_ID=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i # keyward:ignore\n" +
		"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE # AWS's documented example, keyward:ignore\n" +
		"export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"
	p := mustPlan(t, "/tmp/.zshrc", content)

	if len(p.Changes) != 1 || p.Changes[0].Name != "GITHUB_TOKEN" {
		t.Fatalf("Changes = %+v, want only GITHUB_TOKEN", p.Changes)
	}
	var skipped []string
	for _, s := range p.Skips {
		if s.Reason != "marked keyward:ignore" || s.Actionable {
			t.Errorf("%s: reason %q, actionable %v; want %q, not actionable", s.Name, s.Reason, s.Actionable, "marked keyward:ignore")
		}
		skipped = append(skipped, s.Name)
	}
	if want := "GIT_AUTHOR_EMAIL,BUILD_ID,AWS_ACCESS_KEY_ID"; strings.Join(skipped, ",") != want {
		t.Errorf("Skips = %v, want %s", skipped, want)
	}
}

// ===========================================================================
// Diff
// ===========================================================================

// The diff is printed to a terminal, and may be printed by an agent running
// keyward. Showing the old line verbatim would put every secret in the file into
// scrollback and into that agent's context — the exact leak this tool exists to
// prevent.
func TestDiffRedactsValues(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	diff := p.Diff()

	for _, secret := range []string{
		"eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
		"ghp_exampleTokenValue0123456789",
	} {
		if strings.Contains(diff, secret) {
			t.Errorf("diff leaked a secret value:\n%s", diff)
		}
	}

	// It must still be obvious which line changes and what it becomes.
	for _, want := range []string{
		"SPLUNK_MCP_TOKEN",
		"cap://splunk-mcp-token",
		"GITHUB_TOKEN",
		"cap://github-token",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff omits %q:\n%s", want, diff)
		}
	}
}

func TestDiffShowsLineNumbersAndReasons(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	diff := p.Diff()

	// SPLUNK_MCP_TOKEN is on line 8 of rcFile.
	if !strings.Contains(diff, "line 8") {
		t.Errorf("diff does not give a line number:\n%s", diff)
	}
	// It names the kind, as the prefix is part of the value.
	if !strings.Contains(diff, "base64-encoded JSON") || strings.Contains(diff, "eyJ") {
		t.Errorf("diff does not explain why the line was picked without its value:\n%s", diff)
	}
	if !strings.Contains(diff, "hidden") {
		t.Errorf("diff does not indicate the value was withheld:\n%s", diff)
	}
}

func TestDiffListsSkips(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	diff := p.Diff()
	for _, want := range []string{"EDITOR", "AWS_PROFILE", "non-secret"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff omits skipped %q:\n%s", want, diff)
		}
	}
}

// Skips needing attention are listed apart from the ordinary ones. In a real rc
// file there are dozens of the latter, and a possible secret would be lost in them.
func TestDiffSeparatesSkipsNeedingAttention(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile+"export MY_THING=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i\n")
	diff := p.Diff()

	review := strings.Index(diff, "check these yourself")
	alone := strings.Index(diff, "\nleft alone:")
	if review < 0 || alone < 0 {
		t.Fatalf("diff is missing a section:\n%s", diff)
	}
	thing := strings.Index(diff, "MY_THING")
	if thing < review || thing > alone {
		t.Errorf("MY_THING is not in the section needing attention:\n%s", diff)
	}
	if strings.Contains(diff[review:alone], "EDITOR") {
		t.Errorf("an ordinary skip was listed as needing attention:\n%s", diff)
	}
	if strings.Contains(diff, "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i") {
		t.Errorf("diff leaked a possible secret's value:\n%s", diff)
	}
}

// ===========================================================================
// Credential-shaped text keyward cannot move
//
// Comments, trailers, and lines the scanner does not parse are never rewritten,
// and old tokens sit in them. The plan says where such text is, never what it is.
// ===========================================================================

// hide masks each fake value in out, so a failing test never prints one.
func hide(out string, values ...string) string {
	for _, v := range values {
		out = strings.ReplaceAll(out, v, "<fake value>")
	}
	return out
}

// A comment beside a value often holds the token it replaced, in any of the shapes
// credentials take. The rewritten line keeps it, so both sides of the diff show
// only its length.
func TestDiffHidesATrailerShapedLikeACredential(t *testing.T) {
	const value = "ghp_exampleTokenValue0123456789"
	for _, tt := range []struct{ shape, old string }{
		{"prefix", "ghp_oldTokenValue0123456789abcdef"},
		{"hex", "0123456789abcdef0123456789abcdef"},
		{"UUID", "123e4567-e89b-12d3-a456-426614174000"},
		{"split by slashes", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"named", "PGPASSWORD=s3cretpassw0rd"},
		// doctor leaves a placeholder out, but printing hides it all the same.
		{"placeholder", "DATABASE_URL=postgres://app:<password>@localhost:5432/app"},
	} {
		t.Run(tt.shape, func(t *testing.T) {
			diff := mustPlan(t, "/tmp/.zshrc", "export GITHUB_TOKEN="+value+"  # was "+tt.old+"\n").Diff()

			if hide(diff, value, tt.old) != diff {
				t.Errorf("diff shows a value:\n%s", hide(diff, value, tt.old))
			}
			hidden := fmt.Sprintf("  # <%d bytes hidden>\n", len(" was "+tt.old))
			for _, want := range []string{
				"-export GITHUB_TOKEN=<31 bytes hidden>" + hidden,
				"+export GITHUB_TOKEN='cap://github-token'" + hidden,
			} {
				if !strings.Contains(diff, want) {
					t.Errorf("diff lacks %q:\n%s", want, hide(diff, value, tt.old))
				}
			}
		})
	}
}

// Only what looks like a credential is hidden: a note about the value is part of
// what the user approves.
func TestDiffShowsAnOrdinaryTrailer(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", "export GITHUB_TOKEN=ghp_exampleTokenValue0123456789 # work, see https://github.com/settings/tokens\n")
	want := "+export GITHUB_TOKEN='cap://github-token' # work, see https://github.com/settings/tokens\n"
	if diff := p.Diff(); !strings.Contains(diff, want) {
		t.Errorf("diff lacks %q:\n%s", want, hide(diff, "ghp_exampleTokenValue0123456789"))
	}
}

// One line of each kind keyward cannot move a value from.
const unmovableRC = `# ~/.zshrc
# export OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
export GITHUB_TOKEN=ghp_exampleTokenValue0123456789 # was ghp_oldTokenValue0123456789abcdef
export EDITOR=vim # AKIAIOSFODNN7EXAMPLE
alias gh='GITHUB_TOKEN=ghp_aliasTokenValue0123456789 gh'
launchctl setenv NPM_TOKEN npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
declare -x VAULT_TOKEN=hvs.AbCdEfGhIjKlMnOpQrStUvWxYz
set -gx ANTHROPIC_API_KEY sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx
GOOGLE_API_KEY = AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234567
export A=1 GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt
`

// unmovableValues are unmovableRC's fake tokens, none of which may be printed.
var unmovableValues = []string{
	"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
	"ghp_exampleTokenValue0123456789",
	"ghp_oldTokenValue0123456789abcdef",
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_aliasTokenValue0123456789",
	"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
	"hvs.AbCdEfGhIjKlMnOpQrStUvWxYz",
	"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx",
	"AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234567",
	"glpat-AbCdEfGhIjKlMnOpQrSt",
}

// Each line is reported by number and kind, in file order. A trailer on a line
// that is rewritten says so: the user might take the whole line as dealt with.
// The advice is doctor's: it says to rotate, and steers whoever fixes the lines,
// an agent included, away from opening or printing them.
func TestUnmovableReportsEachKindByLine(t *testing.T) {
	out := mustPlan(t, "/tmp/.zshrc", unmovableRC).Unmovable()

	want := "\ncredential-shaped text keyward cannot move:\n" +
		"  line 2 (comment)\n" +
		"  line 3 (trailer): it stays in the rewritten line; remove it by hand\n" +
		"  line 4 (trailer)\n" +
		"  line 5 (alias)\n" +
		"  line 6 (launchctl)\n" +
		"  line 7 (unsupported syntax)\n" +
		"  line 8 (unsupported syntax)\n" +
		"  line 9 (unsupported syntax)\n" +
		"  line 10 (unsupported syntax)\n" +
		"  Remove them by hand in an editor, then rotate any real credential. AI agents must not open or print these lines.\n" +
		"  If a line holds no secret, end it with # keyward:ignore yourself, and keyward leaves the line alone; an AI agent must not.\n"
	if out != want {
		t.Errorf("Unmovable() =\n%s\nwant\n%s", hide(out, unmovableValues...), want)
	}
	if hide(out, unmovableValues...) != out {
		t.Errorf("the report shows a value:\n%s", hide(out, unmovableValues...))
	}
}

// The plan carries the report, ahead of the ordinary skips it would be lost in,
// and still shows no value.
func TestDiffIncludesTheUnmovableReport(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", unmovableRC)
	diff := p.Diff()

	report := strings.Index(diff, "credential-shaped text keyward cannot move:")
	alone := strings.Index(diff, "\nleft alone:")
	if report < 0 || alone < 0 || report > alone || !strings.Contains(diff, p.Unmovable()) {
		t.Errorf("the report is missing from the diff, or follows the ordinary skips:\n%s", hide(diff, unmovableValues...))
	}
	if hide(diff, unmovableValues...) != diff {
		t.Errorf("diff shows a value:\n%s", hide(diff, unmovableValues...))
	}
}

// The patterns: known prefixes, a URL with a password in it, long tokens that mix
// upper case, lower case and digits, hex keys and UUIDs, and base64 that / splits.
func TestUnmovableFindsCredentialShapes(t *testing.T) {
	shapes := []string{
		"old: ghp_exampleTokenValue0123456789",
		"AKIAIOSFODNN7EXAMPLE",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl",
		"Authorization: Bearer Qm2vLp7wRt4yNb8cFj1h",
		"Authorization: Basic dXNlcjpwYXNzd29yZA==",
		// Split so secret scanners do not report this fake token.
		"xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOp",
		"postgres://admin:hunter2@db.internal/prod",
		// The password is literal, though the path expands.
		"curl https://admin:hunter2@db.internal/$DB",
		"Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i",
		// A line from the body of a private key.
		"MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiZ1BjP5CE",
		"old: 0123456789abcdef0123456789abcdef",
		"prev 123E4567-E89B-12D3-A456-426614174000",
		// A hex key inside a longer token. Split so secret scanners do not report it.
		"0123456789abcdef0123456789abcdef" + "-us12",
		// A full stop does not hide the key.
		"was wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.",
	}
	var content strings.Builder
	for _, s := range shapes {
		content.WriteString("# " + s + "\n")
	}
	out := mustPlan(t, "/tmp/.zshrc", content.String()).Unmovable()

	for i := range shapes {
		if !strings.Contains(out, fmt.Sprintf("  line %d (comment)\n", i+1)) {
			t.Errorf("line %d holds a credential shape but was not reported:\n%s", i+1, hide(out, shapes...))
		}
	}
	if hide(out, shapes...) != out {
		t.Errorf("the report shows a value:\n%s", hide(out, shapes...))
	}
}

// An assignment keyward cannot move is judged as Detect judges a plain one, so a
// secret too short or plain to look like one is still found by its name.
func TestUnmovableFindsSecretsByName(t *testing.T) {
	content := "# export PGPASSWORD=s3cretpassw0rd\n" +
		"#ONCALL_TOKEN='Ab3dEf6hIj9lMn2pQr5t'\n" +
		"declare -x METRICS_API_KEY=QX7RT2KL9MZ4WB8NC3VH\n" +
		"export A=1 DB_PASSWORD=s3cretpassw0rd\n" +
		"launchctl setenv DB_PASSWORD s3cretpassw0rd\n" +
		"set -gx DB_PASSWORD 's3cretpassw0rd'\n" +
		"DB_PASSWORD = s3cretpassw0rd\n" +
		"export PGHOST=db.internal # PGPASSWORD=s3cretpassw0rd\n"
	out := hide(mustPlan(t, "/tmp/.zshrc", content).Unmovable(), "s3cretpassw0rd", "Ab3dEf6hIj9lMn2pQr5t", "QX7RT2KL9MZ4WB8NC3VH")

	want := "\ncredential-shaped text keyward cannot move:\n" +
		"  line 1 (comment)\n" +
		"  line 2 (comment)\n" +
		"  line 3 (unsupported syntax)\n" +
		"  line 4 (unsupported syntax)\n" +
		"  line 5 (launchctl)\n" +
		"  line 6 (unsupported syntax)\n" +
		"  line 7 (unsupported syntax)\n" +
		"  line 8 (trailer)\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("Unmovable() =\n%s\nwant it to begin\n%s", out, want)
	}
}

// A value Detect only may call a credential counts too, commented out or not
// parsed, judged as a plain one is: a password does, and so does a single flag, but
// a list of flags does not.
func TestUnmovableFindsValuesThatMayBeCredentials(t *testing.T) {
	content := "# export DB_CONN='Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD'\n" +
		"export A=1 DB_CONN='Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD'\n" +
		`# export CPPFLAGS="-I/Library/Developer/CommandLineTools/SDKs/MacOSX14.sdk/usr/include"` + "\n" +
		`# export CPPFLAGS="-I/opt/homebrew/opt/libpq/include -I/opt/homebrew/opt/openssl@3/include"` + "\n"

	var got []string
	for _, u := range migrate.Scan([]byte(content)).Unmovable() {
		got = append(got, fmt.Sprintf("%d %s %v", u.Line, u.Kind, u.KnownShape))
	}
	if want := "1 comment false, 2 unsupported syntax false, 3 comment false"; strings.Join(got, ", ") != want {
		t.Errorf("Unmovable() = %v, want %s", got, want)
	}
}

// Ordinary rc lines stay out of the report, including URLs, paths, versions, long
// identifiers, credentials the shell expands, and commented-out settings.
func TestUnmovableLeavesOrdinaryLinesAlone(t *testing.T) {
	ordinary := []string{
		"# ~/.zshrc",
		"# personal token, rotate monthly",
		"# see https://github.com/Homebrew/brew/issues/12345",
		"# see https://github.com/SomeOrganisation/SomeRepositoryName2024",
		"# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
		"# python user base: /Users/me/Library/Python/3.11/bin",
		"# notes are in Documents/PersonalNotes/ObsidianVaultBackups",
		"alias proj='cd $HOME/Projects2024/SomeVeryLongProjectName'",
		"alias ext='cd /Volumes/ExternalDrive2024/SomeVeryLongFolderName'",
		"# placeholders: 00000000-0000-0000-0000-000000000000, ffffffff-ffff-ffff-ffff-ffffffffffff",
		`# export CPPFLAGS="-I/Library/Developer/CommandLineTools/SDKs/MacOSX14.sdk/usr/include -I/opt/homebrew/include"`,
		"# Uses Bearer authentication; sk-SK is the Slovak locale",
		"# Basic Authentication for the proxy, Bearer Authentication upstream",
		"# git clone https://oauth2:$GITLAB_TOKEN@gitlab.com/group/repo.git",
		"alias gc='git clone https://${GH_USER}:${GH_TOKEN}@github.com/org/repo.git'",
		`# export SSH_KEY_PATH="~/.ssh/rsa_id"`,
		"# export LANG=en_US.UTF-8",
		"# SomeVeryLongJavaClassNameFactoryBean, python3-pip-install-requirements-2024",
		"# ssh://git@github.com/veilux-lab/keyward.git",
		"# >>> conda initialize >>>",
		`__conda_setup="$('/opt/homebrew/Caskroom/miniforge/base/bin/conda' 'shell.zsh' 'hook' 2> /dev/null)"`,
		"typeset -g POWERLEVEL9K_INSTANT_PROMPT=verbose",
		"alias k='kubectl --context arn:aws:eks:us-west-2:123456789012:cluster/prod'",
		"launchctl setenv PATH /usr/local/bin:/usr/bin:/bin",
		"set -gx PATH /opt/homebrew/bin $PATH",
		"set -gx SSH_KEY_PATH '~/.ssh/id_ed25519'",
		`[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm`,
		"export EDITOR=vim # see https://github.com/veilux-lab/keyward/pull/21",
	}
	p := mustPlan(t, "/tmp/.zshrc", strings.Join(ordinary, "\n")+"\n")
	if out := p.Unmovable(); out != "" {
		t.Errorf("ordinary lines were reported:\n%s", out)
	}
}

// Hashes for the tests of what a comment shows to be no token.
const (
	sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	commitHex = "3f9a2b7c1d8e4f6a0b5c9d2e7f1a4b8c3d6e9f02"
)

// In a comment, hex written after its algorithm, at that algorithm's length, or as
// a commit in a link's path is a hash, not a token.
func TestUnmovableLeavesHashesInCommentsAlone(t *testing.T) {
	ordinary := []string{
		"# pinned to nginx@sha256:" + sha256Hex,
		"# SHA256:" + sha256Hex + " is the release tarball's",
		"# was sha1:" + commitHex,
		"# lockfile sha512-" + sha256Hex + sha256Hex,
		"# https://github.com/example-org/payments/commit/" + commitHex,
		"# https://github.com/example-org/payments/blob/" + commitHex + "/deploy.sh",
		"# https://github.com/example-org/payments/tree/" + commitHex + "?tab=readme",
		"export EDITOR=vim # fixed in https://github.com/example-org/payments/commit/" + commitHex,
	}
	p := mustPlan(t, "/tmp/.zshrc", strings.Join(ordinary, "\n")+"\n")
	if out := p.Unmovable(); out != "" {
		t.Errorf("hashes were reported:\n%s", out)
	}
}

// Only those forms say so. Another word for a hash on the line, a digest without
// its colon or at another length, and hex in an alias are no proof.
func TestUnmovableStillFindsHexBesideWordsForAHash(t *testing.T) {
	shapes := []string{
		"# commit " + commitHex + " fixed the deploy script",
		"# md5 9e107d9d372bb6826bd81d3542a419d6 of the release tarball",
		"# sha256 " + sha256Hex,
		"# sha256:" + sha256Hex[:60],
		"# https://github.com/example-org/payments/commits/" + commitHex,
		"# sha256:" + sha256Hex + "Zx9kQm2vLp7wRt4yNb8cFj1h",
		"alias pin='docker pull nginx@sha256:" + sha256Hex + "'",
	}
	out := mustPlan(t, "/tmp/.zshrc", strings.Join(shapes, "\n")+"\n").Unmovable()
	for i := range shapes {
		if !strings.Contains(out, fmt.Sprintf("  line %d (", i+1)) {
			t.Errorf("line %d holds hex that may be a key but was not reported:\n%s", i+1, out)
		}
	}
}

// In a comment, the path of a link to a host that keeps documents holds a
// document's ID, which looks random but is no token. Beside one, a commit's hash,
// an identifier, another document's ID and a query's short values are none either.
func TestUnmovableLeavesDocumentIDsInCommentsAlone(t *testing.T) {
	ordinary := []string{
		"# see https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit",
		"# https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz012345",
		"# runbook https://www.notion.so/example/Payments-Runbook-9f8e7d6c5b4a39281706fedcba098765",
		"# https://example.notion.site/Onboarding-9f8e7d6c5b4a39281706fedcba098765",
		"# https://gist.github.com/someone/9f8e7d6c5b4a39281706fedcba098765",
		"# demo https://www.loom.com/share/9f8e7d6c5b4a39281706fedcba098765",
		"export EDITOR=vim # design https://www.figma.com/design/AbCdEf1234GhIjKl5678MnOpQr/Checkout",
		"# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit,https://github.com/example-org/payments/commit/" + commitHex,
		"# see https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit for ReactiveOAuth2AuthorizedClientManagerConfigurer",
		"# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit https://www.notion.so/acme/Payments-Runbook-9f8e7d6c5b4a39281706fedcba098765",
		"# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit?usp=sharing&ouid=103906482216797654321&rtpof=true&sd=true",
	}
	p := mustPlan(t, "/tmp/.zshrc", strings.Join(ordinary, "\n")+"\n")
	if out := p.Unmovable(); out != "" {
		t.Errorf("documents' IDs were reported:\n%s", out)
	}
}

// Only the path holds a document's ID: a token in a link's query or fragment, in a
// link to another host, or beside the link is listed as any is, and beside a
// document's ID, one of 30 characters or more is listed whatever it mixes.
func TestUnmovableStillFindsTokensBesideDocumentLinks(t *testing.T) {
	shapes := []string{
		"# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/export?format=txt&access_token=ya29." + "a0AfB_byCxK9mZ2vLp7wRt4yNb8cFj1hGd5sAe3u",
		"# https://docs.google.com/oauth/callback#access_token=ya29." + "a0AfB_byCxK9mZ2vLp7wRt4yNb8cFj1hGd5sAe3u",
		"# https://www.notion.so/example/Runbook?token=0123456789abcdef0123456789abcdef01234567",
		"# https://docs.google.com.example.net/d/Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://mcp.example.com/Ab3dEf6hIj9lMn2pQr5tUv8xYz01/mcp",
		"# https://www.loom.com/share/x Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"alias doc='open https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit'",
		// A path ends at what a document's ID is never written with, or where
		// another URL's scheme starts.
		"# links: https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit,https://hooks.slack." +
			"com/services/T0ABCDEFG/B0ABCDEFG/Ab3dEf6hIj9lMn2pQr5tUv8x",
		"# runbook https://www.notion.so/acme/Runbook-9f8e7d6c5b4a39281706fedcba098765|key=Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edit;Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# (https://docs.google.com/document/d/abc/edit)Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# [https://docs.google.com/document/d/abc/edit]Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# <https://docs.google.com/document/d/abc/edit>Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edithttps://api.example.com/v1/Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"export EDITOR=vim # https://docs.google.com/document/d/abc/edit,Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edit&Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edit=Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://www.notion.so/acme/Runbook-9f8e7d6c5b4a39281706fedcba098765+Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://www.figma.com/design/AbCdEf1234GhIjKl5678MnOpQr/Checkout@Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://www.figma.com/design/AbCdEf1234GhIjKl5678MnOpQr/Checkout!Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edit*Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://www.notion.so/acme/Runbook-9f8e7d6c5b4a39281706fedcba098765~Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edit$Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://docs.google.com/document/d/abc/edit%20Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://www.figma.com/design/AbCdEf1234GhIjKl5678MnOpQr/Checkout%0AAb3dEf6hIj9lMn2pQr5tUv8xYz01",
		"# https://www.notion.so/acme/Runbook-9f8e7d6c5b4a39281706fedcba098765^Ab3dEf6hIj9lMn2pQr5tUv8xYz01",
		`# https://docs.google.com/document/d/abc/edit\nAb3dEf6hIj9lMn2pQr5tUv8xYz01`,
		"# https://docs.google.com/document/d/abc/editAb3dEf6hIj9lMn2pQr5tUv8xYz01https://example.com/next",
		"# https://www.figma.com/design/AbCdEf1234GhIjKl5678MnOpQr/Checkout-Ab3dEf6hIj9lMn2pQr5tUv8xYz01s3://bucket/next",
		"# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit,k3j9x2m1q8w7e6r5t4y3u2i1o0p9a8s7",
		"# https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz012345|key=K3J9X2M1Q8W7E6R5T4Y3U2I1O0P9A8S7",
		"# https://www.notion.so/acme/Runbook-9f8e7d6c5b4a39281706fedcba098765,https://api.example.com/v1/k3j9x2m1q8w7e6r5t4y3u2i1o0p9a8s7",
		"# https://gist.github.com/someone/9f8e7d6c5b4a39281706fedcba098765 K3J9X2M1Q8W7E6R5T4Y3U2I1O0P9A8S7",
		"# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/editk3j9x2m1q8w7e6r5t4y3u2i1o0p9a8s7https://example.com/next",
		"export EDITOR=vim # https://www.loom.com/share/9f8e7d6c5b4a39281706fedcba098765;k3j9x2m1q8w7e6r5t4y3u2i1o0p9a8s7",
	}
	out := mustPlan(t, "/tmp/.zshrc", strings.Join(shapes, "\n")+"\n").Unmovable()
	for i := range shapes {
		if !strings.Contains(out, fmt.Sprintf("  line %d (", i+1)) {
			t.Errorf("line %d holds a token but was not reported:\n%s", i+1, out)
		}
	}
}

// In a comment, a CamelCase identifier, such as a class's name, mixes upper case,
// lower case and digits as a key does, but is made of words and acronyms, so it is
// no token.
func TestUnmovableLeavesCamelCaseIdentifiersInCommentsAlone(t *testing.T) {
	ordinary := []string{
		"# Client: OAuth2AuthorizedClientManager and ReactiveOAuth2AuthorizedClientManager",
		"# Spring Security: OAuth2TokenRelayGatewayFilterFactory, ReactiveOAuth2CredentialsProviderManager",
		"export EDITOR=vim # see ReactiveOAuth2AuthorizedClientManagerConfigurer",
		"# see HTTPServerConnectionFactory2Builder and EC2InstanceMetadataServiceClient",
		"# AWSCredentialsProvider2Chain reads the profile",
	}
	p := mustPlan(t, "/tmp/.zshrc", strings.Join(ordinary, "\n")+"\n")
	if out := p.Unmovable(); out != "" {
		t.Errorf("identifiers were reported:\n%s", out)
	}
}

// A passphrase can read as CamelCase, but its capitalised words hold no acronym an
// identifier is written with, as OAuth is, so one is listed wherever its digits
// are, and where a short word such as I, A, OK, TV or USA runs its capitals into
// the next word's, as are one right after a word for a credential, one with more
// than two digits, one whose digits end it, and one outside a comment.
func TestUnmovableStillFindsCamelCasePassphrases(t *testing.T) {
	shapes := []string{
		"# CorrectHorseOKBattery42Staple",
		"# WatchingTVTonight7Together",
		"# TravellingUSAThisSummer24Again",
		"# RememberingWhatIAteYesterday4Lunch",
		"# WaitingForAPassphrase7Tonight",
		"# vpn password: CorrectHorseBatteryStaple1",
		"# api key: PurpleElephantDancingMoon42",
		"# apiKey=TerribleMondayCoffeeMachine7",
		"# pwd CorrectHorseBatteryStaple1",
		"# old creds: CorrectHorseBatteryStaple1",
		"# root pw: PurpleMonkeyDishwasher42",
		"# wifi password is PurpleMonkeyDishwasher42",
		"# export WIFI_PHRASE=GlacierIrisLotusVortexHarbor9",
		"# PurpleMonkey42DishwasherBlue",
		"# 42PurpleMonkeyDishwasherBlue",
		"# Purple4Monkey7DishwasherBlue",
		"# Lamp42KettleDishwasherBlue",
		"export EDITOR=vim # PurpleMonkeyDishwasher42",
		"# OAuth2Authorized3Client4Manager",
		"# OAuth2AuthorizedClientManagerV2",
		"alias show='echo OAuth2AuthorizedClientManagerConfig'",
	}
	out := mustPlan(t, "/tmp/.zshrc", strings.Join(shapes, "\n")+"\n").Unmovable()
	for i := range shapes {
		if !strings.Contains(out, fmt.Sprintf("  line %d (", i+1)) {
			t.Errorf("line %d holds a token but was not reported:\n%s", i+1, out)
		}
	}
}

// A line known to hold no secret, such as a documented example, can be marked in
// its comment so it is not reported again. Only a comment as the shell reads one
// counts: a marker in a quoted value or inside a word neither stops NewPlan moving
// the line nor hides the line here.
func TestUnmovableHonoursTheIgnoreMarker(t *testing.T) {
	content := "# AWS's documented example key: AKIAIOSFODNN7EXAMPLE  keyward:ignore\n" +
		"alias demo='echo ghp_exampleTokenValue0123456789' # keyward:ignore\n" +
		"export EDITOR=vim # AKIAIOSFODNN7EXAMPLE, keyward:ignore\n" +
		"alias demo2='echo ghp_exampleTokenValue0123456789 keyward:ignore'\n" +
		`export GIT_AUTHOR_EMAIL="someone@example.com#keyward:ignore" # old ghp_exampleTokenValue0123456789` + "\n" +
		`export A="x#keyward:ignore" GITHUB_TOKEN=ghp_exampleTokenValue0123456789` + "\n" +
		`alias demo3="echo \"ghp_exampleTokenValue0123456789 #keyward:ignore"` + "\n" +
		"alias demo4=ghp_exampleTokenValue0123456789#keyward:ignore\n"
	out := hide(mustPlan(t, "/tmp/.zshrc", content).Unmovable(), "AKIAIOSFODNN7EXAMPLE", "ghp_exampleTokenValue0123456789")

	want := "\ncredential-shaped text keyward cannot move:\n  line 4 (alias)\n" +
		"  line 5 (trailer): it stays in the rewritten line; remove it by hand\n" +
		"  line 6 (unsupported syntax)\n" +
		"  line 7 (alias)\n" +
		"  line 8 (alias)\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("Unmovable() =\n%s\nwant it to begin\n%s", out, want)
	}
	if !strings.Contains(out, "keyward:ignore") {
		t.Errorf("the report does not say how to mark a line that holds no secret:\n%s", out)
	}
}

// The note about a kept trailer follows the plan that is approved: a change Check
// turns into a skip leaves its line, trailer and all, as it was.
func TestUnmovableNotesOnlyLinesStillRewritten(t *testing.T) {
	content := "export SPLUNK_MCP_TOKEN=eyJaNewValue0123456789 # was eyJanOlderValue0123456789AbCd\n" +
		"export GITHUB_TOKEN=ghp_exampleTokenValue0123456789 # was ghp_oldTokenValue0123456789abcdef\n"
	p := mustPlan(t, "/tmp/.zshrc", content)
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"splunk-mcp-token": "eyJanOlderValue"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := p.Check(store); err != nil {
		t.Fatalf("Check: %v", err)
	}

	out := hide(p.Unmovable(), "eyJaNewValue0123456789", "eyJanOlderValue0123456789AbCd",
		"ghp_exampleTokenValue0123456789", "ghp_oldTokenValue0123456789abcdef")
	for _, want := range []string{
		"  line 1 (trailer)\n",
		"  line 2 (trailer): it stays in the rewritten line; remove it by hand\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Unmovable() lacks %q:\n%s", want, out)
		}
	}
}

// doctor fails only on text this scan says has a known shape, as Detect says of a
// value: a prefix or URL credentials at a credential's length, or an assignment
// Detect gives one. A name, randomness, or a value too short for its shape only
// suggests a credential.
func TestUnmovableSaysWhichTextHasAKnownShape(t *testing.T) {
	content := "# old: ghp_exampleTokenValue0123456789\n" +
		"export EDITOR=vim # AKIAIOSFODNN7EXAMPLE\n" +
		"alias db='psql postgres://admin:hunter2@db.internal/prod'\n" +
		// Too plain to look like a token in text, but Detect knows its shape.
		"declare -x GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwx\n" +
		"# export PGPASSWORD=s3cretpassw0rd\n" +
		"# export GIT_AUTHOR_EMAIL=someone@example.com\n" +
		"# old: 0123456789abcdef0123456789abcdef\n" +
		"# Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i\n" +
		"# was wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
		"# old: ghp_Ab3dEf6hIj9l\n" +
		"# ftp://me:pw@host\n" +
		// Without NAME=, as Detect measures them, these URLs are too short.
		"# export DATABASE_URL=ftp://me:pw@host\n" +
		"export B=1 DATABASE_URL=ftp://me:pw@host\n"

	var got []string
	for _, u := range migrate.Scan([]byte(content)).Unmovable() {
		got = append(got, fmt.Sprintf("%d %s %v", u.Line, u.Kind, u.KnownShape))
	}
	want := []string{
		"1 comment true", "2 trailer true", "3 alias true", "4 unsupported syntax true",
		"5 comment false", "6 comment false", "7 comment false", "8 comment false",
		"9 comment false", "10 comment false", "11 comment false", "12 comment false",
		"13 unsupported syntax false",
	}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("Unmovable() = %v\nwant %v", got, want)
	}
}

// ===========================================================================
// Check
//
// Conflicts with what is already in the vault have to be found before the plan is
// shown, not while applying it. Otherwise the user approves a plan that is not
// what happens — and one conflict aborts migrations that had nothing to do with it.
// ===========================================================================

// The case that motivated this: a variable is migrated, removed from the file, then
// re-added later with a new value. The vault still holds the old one.
func TestCheckMovesConflictsToSkips(t *testing.T) {
	content := "export SPLUNK_MCP_TOKEN=eyJaNewValue0123456789\n" +
		"export GITHUB_TOKEN=ghp_unrelatedValue0123456789\n"
	p := mustPlan(t, "/tmp/.zshrc", content)

	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"splunk-mcp-token": "eyJanOlderValue"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := p.Check(store); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(p.Changes) != 1 || p.Changes[0].Name != "GITHUB_TOKEN" {
		t.Errorf("Changes = %+v, want only GITHUB_TOKEN so the conflict blocks nothing else", p.Changes)
	}

	var found bool
	for _, s := range p.Skips {
		if s.Name == "SPLUNK_MCP_TOKEN" {
			found = true
			if !strings.Contains(s.Reason, "different value") {
				t.Errorf("skip reason = %q, want it to explain the conflict", s.Reason)
			}
			if !strings.Contains(s.Reason, "splunk-mcp-token") {
				t.Errorf("skip reason = %q, want it to name the vault entry", s.Reason)
			}
			// Both ways out are spelled out, including how to keep the two values.
			if !strings.Contains(s.Reason, "keyward rm splunk-mcp-token") || !strings.Contains(s.Reason, "keyward add <new-name>") ||
				!strings.Contains(s.Reason, "SPLUNK_MCP_TOKEN='cap://<new-name>'") {
				t.Errorf("skip reason = %q, want the commands for both fixes", s.Reason)
			}
		}
	}
	if !found {
		t.Error("the conflicting variable was neither changed nor skipped")
	}
}

// An entry already holding the identical value must stay a change: the vault is
// right but the file still has plaintext in it that needs replacing.
func TestCheckKeepsChangesWhenTheStoredValueMatches(t *testing.T) {
	const token = "eyJaMatchingValue0123456789"
	p := mustPlan(t, "/tmp/.zshrc", "export SPLUNK_MCP_TOKEN="+token+"\n")

	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"splunk-mcp-token": token}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := p.Check(store); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(p.Changes) != 1 {
		t.Errorf("Changes = %+v, want the change kept so the file still gets rewritten", p.Changes)
	}
}

func TestCheckLeavesAbsentNamesAlone(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	before := len(p.Changes)

	if err := p.Check(vault.NewMemory()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(p.Changes) != before {
		t.Errorf("Changes went from %d to %d against an empty vault", before, len(p.Changes))
	}
}

// If the vault cannot be read, Check must not guess. Treating an unreadable entry
// as absent would let Apply overwrite something it could not inspect.
func TestCheckReportsStoreFailure(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	if err := p.Check(unreadableStore{Store: vault.NewMemory()}); err == nil {
		t.Error("Check succeeded against an unreadable store")
	}
}

type unreadableStore struct{ vault.Store }

func (unreadableStore) Get(string) (vault.Secret, error) {
	return vault.Secret{}, errors.New("keychain read failed")
}

// ===========================================================================
// Apply
// ===========================================================================

func TestApply(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()

	p, err := migrate.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	applied, err := p.Apply(store, backups(t))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Secrets are in the vault.
	for name, want := range map[string]string{
		"splunk-mcp-token": "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
		"github-token":     "ghp_exampleTokenValue0123456789",
	} {
		got, err := store.Get(name)
		if err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		if string(got.Bytes()) != want {
			t.Errorf("stored %q incorrectly", name)
		}
	}

	// The file now holds references, and nothing else changed.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the rewritten file: %v", err)
	}
	want := strings.NewReplacer(
		"export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
		"export SPLUNK_MCP_TOKEN='cap://splunk-mcp-token'",
		"export GITHUB_TOKEN='ghp_exampleTokenValue0123456789'",
		"export GITHUB_TOKEN='cap://github-token'",
	).Replace(rcFile)
	if string(after) != want {
		t.Errorf("rewritten file =\n%s\nwant\n%s", after, want)
	}

	if len(applied.Stored) != 2 {
		t.Errorf("Stored = %v, want 2 names", applied.Stored)
	}
	if applied.BackupPath == "" {
		t.Error("Apply reported no backup path")
	}
}

// Provenance is what later lets keyward distinguish an entry whose source file no
// longer references it from one a person added on purpose. Without it, every
// unreferenced entry looks equally like a leftover and none can be safely removed.
func TestApplyRecordsProvenance(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()

	if _, err := mustReadPlan(t, path).Apply(store, backups(t)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	entries, err := store.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	notes := map[string]string{}
	for _, e := range entries {
		notes[e.Name] = e.Note
	}

	// SPLUNK_MCP_TOKEN is on line 8 of rcFile, GITHUB_TOKEN on line 9.
	if want := path + ":8"; notes["splunk-mcp-token"] != want {
		t.Errorf("note = %q, want %q", notes["splunk-mcp-token"], want)
	}
	if want := path + ":9"; notes["github-token"] != want {
		t.Errorf("note = %q, want %q", notes["github-token"], want)
	}

	// A note must never carry the value it describes.
	for _, e := range entries {
		if strings.Contains(e.Note, "eyJ") || strings.Contains(e.Note, "ghp_") {
			t.Errorf("note for %s leaked a value: %q", e.Name, e.Note)
		}
	}
}

func TestApplyWritesAnEncryptedBackupOfTheOriginal(t *testing.T) {
	path := writeRC(t, rcFile)
	p, _ := migrate.Read(path)
	store := vault.NewMemory()
	dir := backups(t)

	applied, err := p.Apply(store, dir)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	raw, err := os.ReadFile(applied.BackupPath)
	if err != nil {
		t.Fatalf("reading the backup: %v", err)
	}
	if strings.Contains(string(raw), "eyJ") || strings.Contains(string(raw), "ghp_") {
		t.Error("the backup holds secrets in plaintext")
	}
	found, _ := dir.ForFile(path)
	if len(found) != 1 {
		t.Fatalf("backups = %+v", found)
	}
	if got, err := backup.Open(store, found[0]); err != nil || string(got.Bytes()) != rcFile {
		t.Errorf("the backup does not decrypt to the original file: %v", err)
	}
	for _, name := range applied.Stored {
		if backup.IsKey(name) {
			t.Errorf("the backup key %s is reported as a migrated secret", name)
		}
	}
	if filepath.Dir(applied.BackupPath) == filepath.Dir(path) {
		t.Error("the backup was written beside the original, where other tools read")
	}
	if info, err := os.Stat(applied.BackupPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the backup is not private to its owner: %v", err)
	}
}

func backups(t *testing.T) backup.Dir {
	t.Helper()
	return backup.Dir{Path: filepath.Join(t.TempDir(), "backups")}
}

func TestApplyPreservesFileMode(t *testing.T) {
	path := writeRC(t, rcFile)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	p, _ := migrate.Read(path)
	if _, err := p.Apply(vault.NewMemory(), backups(t)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600 preserved", got)
	}
}

// Running migrate twice must be safe. The second pass finds only references,
// which Detect skips, so there is nothing left to do.
func TestApplyIsIdempotent(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()

	p, _ := migrate.Read(path)
	if _, err := p.Apply(store, backups(t)); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	afterFirst, _ := os.ReadFile(path)

	p2, err := migrate.Read(path)
	if err != nil {
		t.Fatalf("second Read: %v", err)
	}
	if !p2.Empty() {
		t.Errorf("second plan has %d changes, want none", len(p2.Changes))
	}
	if _, err := p2.Apply(store, backups(t)); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	afterSecond, _ := os.ReadFile(path)
	if string(afterFirst) != string(afterSecond) {
		t.Error("a second Apply changed the file")
	}
}

// Re-running after a partial failure must not stop on ErrExists when the stored
// value is the one we were going to store anyway.
func TestApplyToleratesAlreadyStoredIdenticalValue(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{
		"splunk-mcp-token": "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	p, _ := migrate.Read(path)
	if _, err := p.Apply(store, backups(t)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "cap://splunk-mcp-token") {
		t.Error("the file was not rewritten")
	}
}

// A name already holding a different value is a conflict. Overwriting it could
// destroy a credential that something else depends on, so nothing is touched.
func TestApplyRefusesToOverwriteADifferentValue(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"splunk-mcp-token": "a-different-token"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	p, _ := migrate.Read(path)
	_, err := p.Apply(store, backups(t))
	if err == nil {
		t.Fatal("Apply overwrote a secret that held a different value")
	}
	if !strings.Contains(err.Error(), "splunk-mcp-token") {
		t.Errorf("error = %v, want it to name the conflict", err)
	}

	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was modified despite the failure")
	}
}

// Storing happens before rewriting, so a vault failure leaves the file and its
// plaintext exactly as they were.
func TestApplyLeavesFileUntouchedWhenStoringFails(t *testing.T) {
	path := writeRC(t, rcFile)

	_, err := mustReadPlan(t, path).Apply(brokenPutStore{Store: vault.NewMemory()}, backups(t))
	if err == nil {
		t.Fatal("Apply succeeded despite the store failing")
	}
	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was modified despite the store failing")
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*keyward-backup*")); len(entries) != 0 {
		t.Errorf("a backup was written before the secrets were stored: %v", entries)
	}
}

// Guards against editing the file between a dry run and an apply: the plan would
// be describing lines that have moved.
func TestApplyRefusesIfTheFileChanged(t *testing.T) {
	path := writeRC(t, rcFile)
	p := mustReadPlan(t, path)

	if err := os.WriteFile(path, []byte("export EDITOR=vim\n"), 0o644); err != nil {
		t.Fatalf("rewriting the fixture: %v", err)
	}

	if _, err := p.Apply(vault.NewMemory(), backups(t)); err == nil {
		t.Fatal("Apply proceeded against a file that had changed")
	}
}

func TestApplyLeavesNoTemporaryFiles(t *testing.T) {
	path := writeRC(t, rcFile)
	applied, err := mustReadPlan(t, path).Apply(vault.NewMemory(), backups(t))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		full := filepath.Join(filepath.Dir(path), e.Name())
		if full != path && full != applied.BackupPath {
			t.Errorf("unexpected file left behind: %s", e.Name())
		}
	}
}

func TestApplyOnEmptyPlanChangesNothing(t *testing.T) {
	path := writeRC(t, "export EDITOR=vim\n")
	applied, err := mustReadPlan(t, path).Apply(vault.NewMemory(), backups(t))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if applied.BackupPath != "" {
		t.Error("a backup was written for a plan with no changes")
	}
	if got, _ := os.ReadFile(path); string(got) != "export EDITOR=vim\n" {
		t.Error("the file changed for a plan with no changes")
	}
}

// If the backup cannot be written, the file must not be rewritten. Secrets are
// already in the vault by this point, which is the safe direction: nothing is
// lost, and re-running once the directory is writable finishes the job.
func TestApplyStopsWhenTheBackupCannotBeWritten(t *testing.T) {
	path := writeRC(t, rcFile)
	p := mustReadPlan(t, path)
	store := vault.NewMemory()

	// The backup directory cannot be created inside a read-only parent.
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o700) })

	_, err := p.Apply(store, backup.Dir{Path: filepath.Join(parent, "backups")})
	if err == nil {
		t.Fatal("Apply succeeded with an unwritable directory")
	}
	if !strings.Contains(err.Error(), "backup") {
		t.Errorf("error = %v, want it to say the backup failed", err)
	}
	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was rewritten despite the backup failing")
	}
	// The secrets did get stored, and saying so is what makes the failure
	// recoverable rather than mysterious.
	if names, _ := store.Entries(); len(names) == 0 {
		t.Error("no secrets were stored before the backup was attempted")
	}
}

// storeSecret consults the existing value to decide between "already done" and
// "conflict". If that read fails, it must not guess.
func TestApplyReportsAFailedConflictCheck(t *testing.T) {
	path := writeRC(t, rcFile)
	store := existsButUnreadable{Store: vault.NewMemory()}

	_, err := mustReadPlan(t, path).Apply(store, backups(t))
	if err == nil {
		t.Fatal("Apply succeeded when the conflict check could not be made")
	}
	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was modified despite the failure")
	}
}

type existsButUnreadable struct{ vault.Store }

func (existsButUnreadable) Put(string, vault.Secret, string) error { return vault.ErrExists }
func (existsButUnreadable) Get(string) (vault.Secret, error) {
	return vault.Secret{}, errors.New("keychain read failed")
}

func TestReadMissingFile(t *testing.T) {
	if _, err := migrate.Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("Read succeeded for a file that does not exist")
	}
}

func mustReadPlan(t *testing.T, path string) *migrate.Plan {
	t.Helper()
	p, err := migrate.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return p
}

var errPutFailed = errors.New("keychain write failed")

type brokenPutStore struct{ vault.Store }

func (brokenPutStore) Put(string, vault.Secret, string) error { return errPutFailed }
