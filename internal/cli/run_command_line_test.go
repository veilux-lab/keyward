package cli_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/mask"
	"github.com/veilux-lab/keyward/internal/vault"
)

// unread is a vault that fails the test that reads a value from it.
type unread struct {
	vault.Store
	t *testing.T
}

func (s unread) Get(name string) (vault.Secret, error) {
	s.t.Errorf("read %s from the vault", name)
	return vault.Secret{}, vault.ErrDenied
}

var (
	jiraValues = map[string]string{"jira-api-email": "fake-user@example.com", "jira-api-token": "FakeJiraToken-0123456789"}
	jiraEnv    = []string{"PATH=/usr/bin:/bin", "JIRA_API_EMAIL=cap://jira-api-email", "JIRA_API_TOKEN=cap://jira-api-token"}
	jiraScript = `curl -s -u "$JIRA_API_EMAIL:$JIRA_API_TOKEN" "https://jira.example.com/rest/api/3/myself"`
)

// The leak this exists for: an agent's sh -c script expands a token into curl's
// command line, where other programs and security logs can read it. keyward run
// refuses before it reads the vault, so nothing is resolved and nothing runs,
// masked or not, and it says how to send the values on stdin instead, naming
// each variable, the program and the line, but nothing the script holds.
func TestRunRefusesAScriptThatPutsAValueInACommandLine(t *testing.T) {
	want := "keyward run: curl would get JIRA_API_EMAIL in its command line (line 1), where other programs and security logs can read it.\n" +
		"keyward run: curl would get JIRA_API_TOKEN in its command line (line 1), where other programs and security logs can read it.\n" +
		`  Send it on stdin instead: printf 'user = "%s:%s"\n' "$JIRA_API_EMAIL" "$JIRA_API_TOKEN" | curl -K - ...` + "\n" +
		"  --allow-command-line runs it anyway, which an AI agent must not add unless the user asks.\n"
	for name, tc := range map[string]struct {
		args     []string
		terminal bool
	}{
		"masked":         {args: []string{"run", "--only", "JIRA_API_EMAIL,JIRA_API_TOKEN", "--", "sh", "-c", jiraScript}},
		"with --no-mask": {args: []string{"run", "--no-mask", "--only", "JIRA_API_EMAIL,JIRA_API_TOKEN", "--", "sh", "-c", jiraScript}},
		"at a terminal":  {args: []string{"run", "--only", "JIRA_API_EMAIL,JIRA_API_TOKEN", "--", "sh", "-c", jiraScript}, terminal: true},
		"without --only": {args: []string{"run", "--", "sh", "-c", jiraScript}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "", jiraValues, jiraEnv)
			h.cli.Store = unread{h.store, t}
			m := withMasking(h, mask.Exit{})
			h.cli.TerminalOut, h.cli.TerminalErr = tc.terminal, tc.terminal
			if code := h.cli.Run(tc.args); code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			if m.calls != 0 || h.exec.calls != 0 {
				t.Errorf("RunMasked ran %d times and exec %d times, want neither", m.calls, h.exec.calls)
			}
			if h.err() != want {
				t.Errorf("stderr =\n%s\nwant\n%s", h.err(), want)
			}
		})
	}
}

// With stderr's reader gone, as when an agent's pipe has closed, the refusal
// cannot be written, but it is still recorded as denied, and nothing runs.
func TestRunRecordsARefusalWhenStderrHasNoReader(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestRunRefusalChild$")
	child.Env = append(os.Environ(), "KEYWARD_REFUSAL_CHILD=1")
	child.Stderr = w
	out, err := child.Output()
	if err != nil || !strings.Contains(string(out), "command//denied\n") {
		t.Errorf("child: %v, recorded:\n%s", err, out)
	}
}

// TestRunRefusalChild is keyward run for TestRunRecordsARefusalWhenStderrHasNoReader,
// with stderr on fd 2, where a write with no reader ends a Go program by SIGPIPE.
func TestRunRefusalChild(t *testing.T) {
	if os.Getenv("KEYWARD_REFUSAL_CHILD") == "" {
		t.Skip("subprocess helper")
	}
	h := newHarness(t, "", jiraValues, jiraEnv)
	h.cli.Store = unread{h.store, t}
	h.cli.Stderr = os.Stderr
	h.cli.Record = func(e activity.Event) { fmt.Printf("%s/%s/%s\n", e.Operation, e.Name, e.Outcome) }
	if code := h.cli.Run([]string{"run", "--only", "JIRA_API_TOKEN", "--", "sh", "-c", jiraScript}); code != 2 || h.exec.calls != 0 {
		t.Errorf("exit code = %d, exec ran %d times; want 2 and nothing run", code, h.exec.calls)
	}
}

// Each finding names its own variable, program and line, and each fix follows
// the findings it covers. What the script holds is never shown, such as a
// credential written into it beside a value.
func TestRunNamesEachFindingButNotWhatTheScriptHolds(t *testing.T) {
	const written = "FakeWrittenCredential0123"
	script := "set -e\n" +
		`curl -H "X-Api-Key: $API_KEY" -d "client=` + written + `&key=$API_KEY" https://api.example.com/v1` + "\n" +
		`mysql -u app -p"$DB_PASSWORD" -h db.example.com`
	h := newHarness(t, "", map[string]string{"api-key": "FakeApiKey-0123456789", "db-password": "FakeDbPassword-0123"},
		[]string{"PATH=/usr/bin:/bin", "API_KEY=cap://api-key", "DB_PASSWORD=cap://db-password"})
	h.cli.Store = unread{h.store, t}
	if code := h.cli.Run([]string{"run", "--", "bash", "-lc", script}); code != 2 || h.exec.calls != 0 {
		t.Fatalf("exit code = %d, exec ran %d times; want 2 and nothing run", code, h.exec.calls)
	}
	want := "keyward run: curl would get API_KEY in its command line (line 2), where other programs and security logs can read it.\n" +
		`  Send it on stdin instead: printf 'header = "X-Api-Key: %s"\ndata = "...%s"\n' "$API_KEY" "$API_KEY" | curl -K - ...` + "\n" +
		"keyward run: mysql would get DB_PASSWORD in its command line (line 3), where other programs and security logs can read it.\n" +
		`  Pass it in the environment instead: MYSQL_PWD="$DB_PASSWORD" mysql ...` + "\n" +
		"  --allow-command-line runs it anyway, which an AI agent must not add unless the user asks.\n"
	if h.err() != want {
		t.Errorf("stderr =\n%s\nwant\n%s", h.err(), want)
	}
	for _, shown := range []string{written, "example.com", "set -e", "FakeApiKey-0123456789", "FakeDbPassword-0123"} {
		if strings.Contains(h.err(), shown) {
			t.Errorf("stderr shows %q", shown)
		}
	}
}

// eval, trap and alias are builtins, with no command line, and a shell gets a
// script it reads on stdin there, not in its command line: each would run the
// value as code, which the message says instead.
func TestRunSaysWhenAValueWouldRunAsCode(t *testing.T) {
	for _, tc := range []struct{ script, want string }{
		{`eval "curl -u u:$JIRA_API_TOKEN x"`, "keyward run: eval would run the value of JIRA_API_TOKEN as code (line 1), which can put it in a program's command line.\n" +
			`  Write the code in single quotes, so it reads "$JIRA_API_TOKEN" only as it runs: eval '... "$JIRA_API_TOKEN" ...'` + "\n"},
		{`trap "curl -u u:$JIRA_API_TOKEN x" EXIT`, "keyward run: trap would run the value of JIRA_API_TOKEN as code (line 1), which can put it in a program's command line.\n"},
		{`alias jc="curl -u u:$JIRA_API_TOKEN"`, "keyward run: alias would run the value of JIRA_API_TOKEN as code (line 1), which can put it in a program's command line.\n"},
		{`printf 'curl -u u:%s x' "$JIRA_API_TOKEN" | sh`, "keyward run: sh would run the value of JIRA_API_TOKEN as code (line 1), which can put it in a program's command line.\n" +
			`  Let sh read "$JIRA_API_TOKEN" from its environment instead: sh -c '... "$JIRA_API_TOKEN" ...'` + "\n"},
	} {
		h := newHarness(t, "", jiraValues, jiraEnv)
		h.cli.Store = unread{h.store, t}
		if code := h.cli.Run([]string{"run", "--only", "JIRA_API_TOKEN", "--", "sh", "-c", tc.script}); code != 2 || h.exec.calls != 0 {
			t.Errorf("%s: exit code = %d, exec ran %d times; want 2 and nothing run", tc.script, code, h.exec.calls)
		}
		if !strings.HasPrefix(h.err(), tc.want) {
			t.Errorf("%s: stderr =\n%s\nwant it to start\n%s", tc.script, h.err(), tc.want)
		}
	}
}

// The script of a shell started through a launcher, as env, nohup, time and
// sudo start one, or by another program, as find -exec does, is checked all
// the same, as it is inside a script.
func TestRunChecksTheScriptOfAShellBehindALauncher(t *testing.T) {
	for _, argv := range [][]string{
		{"env", "LC_ALL=C", "sh", "-c", jiraScript},
		{"nohup", "/bin/zsh", "-o", "pipefail", "-c", jiraScript},
		{"env", "A.B=1", "sh", "-c", jiraScript},
		{"/usr/bin/time", "-p", "sh", "-c", jiraScript},
		{"sudo", "-E", "bash", "-c", jiraScript},
		{"xargs", "-0", "sh", "-c", jiraScript},
		{"find", ".", "-maxdepth", "0", "-exec", "sh", "-c", jiraScript, ";"},
	} {
		h := newHarness(t, "", jiraValues, jiraEnv)
		h.cli.Store = unread{h.store, t}
		if code := h.cli.Run(append([]string{"run", "--only", "JIRA_API_TOKEN", "--"}, argv...)); code != 2 || h.exec.calls != 0 {
			t.Errorf("%q: exit code = %d, exec ran %d times; want 2 and nothing run", argv, code, h.exec.calls)
		}
		if !strings.HasPrefix(h.err(), "keyward run: curl would get JIRA_API_TOKEN in its command line (line 1)") {
			t.Errorf("%q: stderr = %q", argv, h.err())
		}
	}
}

// Only a value keyward run fills in counts: not a variable --only leaves out,
// nor one that holds no reference. A script that keeps its values out of
// command lines, as the safe form does, runs, and so does a command that is
// not a shell's script.
func TestRunStartsAScriptThatPutsNoResolvedValueInACommandLine(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--only", "JIRA_API_EMAIL", "--", "sh", "-c", `curl -H "X-Token: $JIRA_API_TOKEN" x`},
		{"run", "--only", "PLAIN", "--", "sh", "-c", `curl -H "X-Key: $PLAIN" x`},
		{"run", "--", "sh", "-c", `curl -H "X-Key: $PLAIN" x`},
		{"run", "--", "sh", "-c", `printf 'user = "%s:%s"\n' "$JIRA_API_EMAIL" "$JIRA_API_TOKEN" | curl -K - https://jira.example.com`},
		{"run", "--", "curl", "-u", "$JIRA_API_EMAIL:$JIRA_API_TOKEN", "x"},
	} {
		h := newHarness(t, "", jiraValues, append(slices.Clone(jiraEnv), "PLAIN=not-a-reference"))
		if code := h.cli.Run(args); code != 0 || h.exec.calls != 1 {
			t.Errorf("%q: exit code = %d, exec ran %d times; want it run. stderr: %s", args, code, h.exec.calls, h.err())
		}
	}
}

// Agents copy the guide's commands as written, so keyward run starts each
// script the guide gives.
func TestRunStartsTheScriptsInTheAgentGuide(t *testing.T) {
	commands := regexp.MustCompile(`([A-Z_]+)=cap://([a-z-]+) keyward run --only [A-Z_]+ -- sh -c '([^']*)'`).FindAllStringSubmatch(string(agents.Instructions()), -1)
	if len(commands) < 2 {
		t.Fatalf("found %d of the guide's sh -c commands, want its header and URL examples", len(commands))
	}
	for _, c := range commands {
		variable, name, script := c[1], c[2], c[3]
		h := newHarness(t, "", map[string]string{name: "fake-guide-value"}, []string{"PATH=/usr/bin:/bin", variable + "=cap://" + name})
		if code := h.cli.Run([]string{"run", "--only", variable, "--", "sh", "-c", script, "_", "https://api.example.com"}); code != 0 || h.exec.calls != 1 {
			t.Errorf("%s: exit code = %d. stderr: %s", script, code, h.err())
		}
	}
}

// The README's example of a script keyward run refuses shows the safe form that
// keyward run prints for it.
func TestTheReadmeShowsTheSafeFormKeywardRunPrints(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(data)), " ")
	example := regexp.MustCompile("as `(curl [^`]+)` would\\. [^`]*the safe form, here `([^`]+)`").FindStringSubmatch(text)
	if example == nil {
		t.Fatal("README lacks its example of a script keyward run refuses")
	}
	h := newHarness(t, "", map[string]string{"api-token": "FakeApiToken-0123456789"}, []string{"PATH=/usr/bin:/bin", "API_TOKEN=cap://api-token"})
	h.cli.Store = unread{h.store, t}
	h.cli.Run([]string{"run", "--only", "API_TOKEN", "--", "sh", "-c", example[1]})
	if !strings.Contains(h.err(), "\n  Send it on stdin instead: "+example[2]+"\n") {
		t.Errorf("for %s, keyward run printed\n%s\nnot the README's safe form %s", example[1], h.err(), example[2])
	}
}

// --allow-command-line runs the script anyway, with the values it needs.
func TestRunAllowCommandLineRunsTheScriptAnyway(t *testing.T) {
	h := newHarness(t, "", jiraValues, jiraEnv)
	args := []string{"sh", "-c", jiraScript}
	if code := h.cli.Run(append([]string{"run", "--allow-command-line", "--only", "JIRA_API_EMAIL,JIRA_API_TOKEN", "--"}, args...)); code != 0 || h.exec.calls != 1 {
		t.Fatalf("exit code = %d, exec ran %d times. stderr: %s", code, h.exec.calls, h.err())
	}
	if !slices.Equal(h.exec.argv, args) || !slices.Contains(h.exec.env, "JIRA_API_TOKEN="+jiraValues["jira-api-token"]) {
		t.Errorf("argv = %q; the value was not resolved", h.exec.argv)
	}
	if h.err() != "" {
		t.Errorf("stderr = %q, want nothing", h.err())
	}
}

// A script keyward run cannot read is refused only if it names a value it
// fills in, which the parser's message and a hint for it say. zsh's own
// syntax, which the parser reads only in part, is the usual cause; an sh
// script is already in sh syntax, so its hint is to fix it.
func TestRunRefusesAScriptItCannotReadOnlyIfItNamesAValue(t *testing.T) {
	for _, tc := range []struct{ shell, script, want string }{
		{"zsh", `for x (a b) curl -u "u:$JIRA_API_TOKEN" "$x"`,
			"keyward run: cannot read the script zsh -c runs, to check where its values go: line 1: `for foo` must be followed by `in`, `do`, `;`, or a newline\n" +
				"  Write it in sh syntax for sh -c, which keyward run can read.\n"},
		{"sh", `if [ -n "$JIRA_API_TOKEN" ]; then curl -u "u:$JIRA_API_TOKEN" x`,
			"keyward run: cannot read the script sh -c runs, to check where its values go: line 1: `if` statement must end with `fi`\n" +
				"  Fix its syntax, so keyward run can read it.\n"},
	} {
		h := newHarness(t, "", jiraValues, jiraEnv)
		h.cli.Store = unread{h.store, t}
		if code := h.cli.Run([]string{"run", "--only", "JIRA_API_TOKEN", "--", tc.shell, "-c", tc.script}); code != 2 || h.exec.calls != 0 {
			t.Errorf("%s: exit code = %d, exec ran %d times; want 2 and nothing run", tc.script, code, h.exec.calls)
		}
		if want := tc.want + "  --allow-command-line runs it anyway, which an AI agent must not add unless the user asks.\n"; h.err() != want {
			t.Errorf("stderr =\n%s\nwant\n%s", h.err(), want)
		}
	}

	h := newHarness(t, "", jiraValues, jiraEnv)
	if code := h.cli.Run([]string{"run", "--only", "JIRA_API_TOKEN", "--", "zsh", "-c", `for x (a b) print -r -- "$x"`}); code != 0 || h.exec.calls != 1 {
		t.Errorf("exit code = %d, exec ran %d times; want it run. stderr: %s", code, h.exec.calls, h.err())
	}
}
