package cli_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/mask"
)

// masked records what run handed to RunMasked, and answers with exit.
type masked struct {
	calls   int
	argv    []string
	env     []string
	secrets []mask.Secret
	exit    mask.Exit
	err     error
	died    syscall.Signal
}

// withMasking gives h a RunMasked that records its call, with stdout and stderr
// not terminals, as for an agent's command.
func withMasking(h *harness, exit mask.Exit) *masked {
	m := &masked{exit: exit}
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		m.calls++
		m.argv, m.env, m.secrets = argv, env, secrets
		return m.exit, m.err
	}
	h.cli.Die = func(sig syscall.Signal) { m.died = sig }
	return m
}

func TestRunHidesValuesInOutputThatIsNotATerminal(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	m := withMasking(h, mask.Exit{Code: 3, Masked: []string{"t"}, MidLine: true})

	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 3 {
		t.Errorf("exit code = %d, want the command's 3", code)
	}
	if m.calls != 1 || h.exec.calls != 0 {
		t.Fatalf("RunMasked ran %d times and exec %d times", m.calls, h.exec.calls)
	}
	if len(m.secrets) != 1 || m.secrets[0] != (mask.Secret{Name: "t", Value: token}) {
		t.Errorf("secrets = %v", m.secrets)
	}
	if !slices.Contains(m.env, "T="+token) {
		t.Errorf("the command's environment lacks the value: %v", m.env)
	}
	want := "\nkeyward run: printenv printed the value of t, masked in the output\n"
	if !strings.HasPrefix(h.err(), want) || !strings.Contains(h.err(), "curl user with no\n  password") {
		t.Errorf("stderr = %q, want it to start with %q and explain", h.err(), want)
	}
	// It may have been printed on purpose, as by cat reading a file.
	if !strings.Contains(h.err(), "If it was not meant to print it, change the command;\n  do not look for the value.") {
		t.Errorf("stderr = %q, want it to say what to do if the value was not meant to show", h.err())
	}
	if strings.Contains(h.out()+h.err(), token) {
		t.Error("run printed the secret")
	}
}

func TestRunLeavesOutputAloneWhereMaskingIsNotNeeded(t *testing.T) {
	for name, tc := range map[string]struct {
		args     []string
		seed     string
		env      []string
		terminal bool
	}{
		"at a terminal":            {args: []string{"run", "--", "printenv"}, seed: token, terminal: true},
		"with --no-mask":           {args: []string{"run", "--no-mask", "--", "printenv"}, seed: token},
		"with --no-mask after":     {args: []string{"run", "--only", "T", "--no-mask", "printenv"}, seed: token},
		"with --no-mask before":    {args: []string{"run", "--no-mask", "--only=T", "printenv"}, seed: token},
		"for a short value":        {args: []string{"run", "--", "printenv"}, seed: "1234567"},
		"for a value in plain env": {args: []string{"run", "--", "printenv"}, seed: "nnwokolo", env: []string{"HOME=/Users/nnwokolo"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "", map[string]string{"t": tc.seed}, append([]string{"PATH=/usr/bin:/bin", "T=cap://t"}, tc.env...))
			m := withMasking(h, mask.Exit{})
			h.cli.TerminalOut, h.cli.TerminalErr = tc.terminal, tc.terminal
			if code := h.cli.Run(tc.args); code != 0 {
				t.Fatalf("exit code = %d: %s", code, h.err())
			}
			if m.calls != 0 || h.exec.calls != 1 {
				t.Errorf("RunMasked ran %d times and exec %d times, want exec only", m.calls, h.exec.calls)
			}
			if !slices.Contains(h.exec.env, "T="+tc.seed) {
				t.Errorf("exec lacks the value: %v", h.exec.env)
			}
		})
	}
}

// Either stream alone being a terminal still masks, as keyward run -- cat f |
// cat does in a tool that runs commands in a terminal, which the guide says.
func TestRunMasksOutputWhenOnlyOneStreamIsATerminal(t *testing.T) {
	for _, out := range []bool{true, false} {
		h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
		m := withMasking(h, mask.Exit{})
		h.cli.TerminalOut, h.cli.TerminalErr = out, !out
		h.cli.Run([]string{"run", "--", "printenv"})
		if m.calls != 1 || h.exec.calls != 0 {
			t.Errorf("stdout a terminal %v, stderr %v: RunMasked ran %d times and exec %d times", out, !out, m.calls, h.exec.calls)
		}
	}
}

func TestRunEndsWithTheSignalThatEndedTheCommand(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	var events []activity.Event
	h.cli.Record = func(e activity.Event) { events = append(events, e) }
	m := withMasking(h, mask.Exit{Code: 128 + 15, Signal: syscall.SIGTERM})
	// The real Die does not return, so the command is recorded before it.
	h.cli.Die = func(sig syscall.Signal) {
		m.died = sig
		if !slices.ContainsFunc(events, func(e activity.Event) bool { return e.Operation == "command" && e.Outcome == "error" }) {
			t.Errorf("Die came before the command was recorded: %v", events)
		}
	}
	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 143 || m.died != syscall.SIGTERM {
		t.Errorf("exit code = %d and died of %v, want SIGTERM", code, m.died)
	}
	if h.err() != "" {
		t.Errorf("stderr = %q, want nothing when no value was hidden", h.err())
	}
}

func TestRunReportsACommandThatCannotStart(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	m := withMasking(h, mask.Exit{})
	m.err = errors.New("permission denied")
	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 1 || !strings.Contains(h.err(), "keyward run: executing printenv: permission denied") {
		t.Errorf("exit code = %d, stderr = %q", code, h.err())
	}
}

// A command's own exit code is recorded as an error, never as keyward's usage
// error, and each hidden secret is recorded by name, before the notice, which
// may never finish.
func TestRunRecordsTheCommandsOutcomeAndHiddenNames(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	var events []activity.Event
	h.cli.Record = func(e activity.Event) {
		if e.Operation == "mask" && h.err() != "" {
			t.Errorf("%s was recorded after stderr got %q", e.Name, h.err())
		}
		events = append(events, e)
	}
	withMasking(h, mask.Exit{Code: 2, Masked: []string{"t"}, MidLine: true})
	h.cli.Run([]string{"run", "--", "printenv"})
	for _, want := range []activity.Event{
		{Command: "run", Operation: "mask", Name: "t", Outcome: "ok"},
		{Command: "run", Operation: "command", Outcome: "error"},
	} {
		if !slices.ContainsFunc(events, func(e activity.Event) bool { e.DurationMS = 0; return e == want }) {
			t.Errorf("events %v lack %v", events, want)
		}
	}
}

// With stderr's reader gone, as in keyward run -- cmd 2>&1 | head -n1, the notice
// cannot be written, but what was hidden and how the command ended are recorded.
func TestRunRecordsWhenStderrHasNoReader(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestRunNoticeChild$")
	child.Env = append(os.Environ(), "KEYWARD_NOTICE_CHILD=1")
	child.Stderr = w
	out, err := child.Output()
	if err != nil || !strings.Contains(string(out), "mask/t/ok\n") || !strings.Contains(string(out), "command//error\n") {
		t.Errorf("child: %v, recorded:\n%s", err, out)
	}
}

// TestRunNoticeChild is keyward run for TestRunRecordsWhenStderrHasNoReader, with
// stderr on fd 2, where a write with no reader ends a Go program by SIGPIPE.
func TestRunNoticeChild(t *testing.T) {
	if os.Getenv("KEYWARD_NOTICE_CHILD") == "" {
		t.Skip("subprocess helper")
	}
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	h.cli.Stderr = os.Stderr
	h.cli.Record = func(e activity.Event) { fmt.Printf("%s/%s/%s\n", e.Operation, e.Name, e.Outcome) }
	withMasking(h, mask.Exit{Code: 1, Masked: []string{"t"}})
	h.cli.Run([]string{"run", "--", "printenv"})
}

// The leak that masking exists for: curl given a token as a user with no
// password asks for one, naming the user, on stderr, which an agent captures.
func TestRunHidesTheTokenInCurlsPasswordPrompt(t *testing.T) {
	h := newHarness(t, "", map[string]string{"jenkins-token": token}, []string{"PATH=/usr/bin:/bin", "JENKINS=cap://jenkins-token"})
	out, err := os.Create(filepath.Join(t.TempDir(), "captured"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	h.cli.Stdout, h.cli.Stderr = out, out
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: out, Stderr: out})
	}
	code := h.cli.Run([]string{"run", "--only", "JENKINS", "--", "sh", "-c", `printf "Enter host password for user '%s':" "$JENKINS" >&2; exit 1`})
	captured, _ := os.ReadFile(out.Name())
	want := "Enter host password for user 'cap://jenkins-token#masked':\nkeyward run: sh printed the value of jenkins-token, masked in the output\n"
	if code != 1 || !strings.HasPrefix(string(captured), want) || strings.Contains(string(captured), token) {
		t.Errorf("exit code %d, captured:\n%s", code, captured)
	}
}

// A program that runs keyward run to read a value, such as a credential helper,
// gets the placeholder, and the command still exits 0. The notice says such
// output needs --no-mask, which an agent must not add unless the user asks.
func TestRunHandsACredentialHelperThePlaceholderAndSaysWhy(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: out, Stderr: out})
	}
	code := h.cli.Run([]string{"run", "--only", "T", "--", "printenv", "T"})
	if shown, _ := os.ReadFile(out.Name()); code != 0 || string(shown) != mask.Placeholder("t")+"\n" {
		t.Errorf("exit code %d, output %q", code, shown)
	}
	want := "Output meant to carry the value, like a credential helper's,\n  needs keyward run --no-mask, which an AI agent must not add unless the user asks.\n"
	if !strings.HasSuffix(h.err(), want) || strings.Contains(h.err(), token) {
		t.Errorf("stderr = %q, want it to end %q", h.err(), want)
	}
}

// The README's masking bullet says the same of a credential helper.
func TestTheReadmeSaysACredentialHelperNeedsNoMask(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "A program that runs `keyward run` to read a value, such as a credential helper like git's `credential.helper` or Claude Code's `apiKeyHelper`, gets the placeholder instead, so such a command needs `--no-mask`."
	if text := strings.Join(strings.Fields(string(data)), " "); !strings.Contains(text, want) {
		t.Errorf("README lacks %q", want)
	}
}

// A plain variable that holds a secret URL-encoded is any program's to read, so
// printing it shows the variable as it is, and names no secret.
func TestRunLeavesAPlainVariableHoldingASecretAlone(t *testing.T) {
	dbURL := "postgres://app:Fake%40Passw0rd%3A2026@db/app"
	h := newHarness(t, "", map[string]string{"db-password": "Fake@Passw0rd:2026"}, []string{"PATH=/usr/bin:/bin", "PGPASSWORD=cap://db-password", "DATABASE_URL=" + dbURL})
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: out, Stderr: out})
	}
	code := h.cli.Run([]string{"run", "--", "sh", "-c", `printf '%s\n' "$DATABASE_URL"`})
	if shown, _ := os.ReadFile(out.Name()); code != 0 || string(shown) != dbURL+"\n" || h.err() != "" {
		t.Errorf("exit code %d, output %q, stderr %q", code, shown, h.err())
	}
}

// A secret inside another's value is hidden under the other's placeholder. The
// notice names both, but no placeholder the output lacks.
func TestRunNamesEachSecretPrintedButNoPlaceholderTheOutputLacks(t *testing.T) {
	inner := "FakeInnerValue0123"
	h := newHarness(t, "", map[string]string{"inner": inner, "outer": "FakeOuter-" + inner}, []string{"PATH=/usr/bin:/bin", "INNER=cap://inner", "OUTER=cap://outer"})
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: out, Stderr: out})
	}
	if code := h.cli.Run([]string{"run", "--", "sh", "-c", `printf %s "$OUTER"`}); code != 0 {
		t.Errorf("exit code = %d", code)
	}
	shown, _ := os.ReadFile(out.Name())
	for _, name := range []string{"inner", "outer"} {
		if !strings.Contains(h.err(), "printed the value of "+name) {
			t.Errorf("stderr = %q, want %s named", h.err(), name)
		}
		if p := mask.Placeholder(name); strings.Contains(h.err(), p) && !strings.Contains(string(shown), p) {
			t.Errorf("stderr = %q names %s, which the output %q lacks", h.err(), p, shown)
		}
	}
}

// Output that did not reach its destination is a failure even when the command
// succeeded; a command that failed keeps its own code.
func TestRunFailsWhenTheOutputCannotBePassedOn(t *testing.T) {
	for _, tc := range []struct{ code, want int }{{0, 1}, {3, 3}} {
		h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
		withMasking(h, mask.Exit{Code: tc.code, Err: syscall.EBADF})
		code := h.cli.Run([]string{"run", "--", "printenv"})
		if code != tc.want || !strings.Contains(h.err(), "keyward run: passing on the output of printenv: bad file descriptor\n") {
			t.Errorf("command exit code %d: exit code = %d, want %d; stderr = %q", tc.code, code, tc.want, h.err())
		}
	}
}

// After stderr's last output, as a progress meter's, ends mid-line, keyward
// run's messages start on a line of their own, a failure's too, and only once.
func TestRunStartsItsMessagesOnANewLine(t *testing.T) {
	failed := "keyward run: passing on the output of printenv: bad file descriptor\n"
	for _, tc := range []struct {
		exit mask.Exit
		want string
	}{
		{mask.Exit{Code: 128 + 13, Signal: syscall.SIGPIPE, MidLine: true, Err: syscall.EBADF}, "\n" + failed},
		{mask.Exit{Masked: []string{"t"}, MidLine: true, Err: syscall.EBADF}, "\n" + failed + "keyward run: printenv printed the value of t"},
	} {
		h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
		withMasking(h, tc.exit)
		if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 1 || !strings.HasPrefix(h.err(), tc.want) {
			t.Errorf("%+v: exit code %d, stderr = %q, want it to start %q", tc.exit, code, h.err(), tc.want)
		}
	}
}

// As yes 1</dev/null stops at once and exits 1, so does keyward run with stdout
// open only for reading, rather than ending by the SIGPIPE that stops yes.
func TestRunFailsWhenStdoutCannotBeWritten(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	readOnly, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: readOnly})
	}
	var died syscall.Signal
	h.cli.Die = func(sig syscall.Signal) { died = sig }
	ran := make(chan int, 1)
	go func() { ran <- h.cli.Run([]string{"run", "--", "yes"}) }()
	select {
	case code := <-ran:
		if code != 1 || died != 0 || !strings.Contains(h.err(), "keyward run: passing on the output of yes: write /dev/null: bad file descriptor\n") {
			t.Errorf("exit code = %d, died of %v, stderr = %q", code, died, h.err())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("yes did not stop")
	}
}

// A reader that has gone, as in keyward run -- yes | head -n 1, still ends the
// command by SIGPIPE, and keyward by the same signal.
func TestRunEndsBySIGPIPEWhenStdoutHasNoReader(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: w})
	}
	var died syscall.Signal
	h.cli.Die = func(sig syscall.Signal) { died = sig }
	if code := h.cli.Run([]string{"run", "--", "yes"}); code != 128+13 || died != syscall.SIGPIPE || h.err() != "" {
		t.Errorf("exit code = %d, died of %v, stderr = %q; want SIGPIPE", code, died, h.err())
	}
}

// On a full disk keyward run closes the command's pipe, so SIGPIPE stops the
// command at its next write, and keyward run fails, rather than ending by
// SIGPIPE, which would say the reader went away.
func TestRunFailsWhenTheDiskIsFull(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunFullDiskChild$")
	child.Env = append(os.Environ(), "KEYWARD_FULL_DISK_CHILD="+t.TempDir())
	// A group of its own, so that the command goes with it should it not stop.
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	child.Cancel = func() error { return syscall.Kill(-child.Process.Pid, syscall.SIGKILL) }
	out, err := child.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the command did not stop\n%s", out)
	}
	if err != nil {
		t.Errorf("child: %v\n%s", err, out)
	}
}

// TestRunFullDiskChild is keyward run for TestRunFailsWhenTheDiskIsFull, with a
// limit on the size of the files it writes standing for a full disk.
func TestRunFullDiskChild(t *testing.T) {
	dir := os.Getenv("KEYWARD_FULL_DISK_CHILD")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = 64 << 10
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	dump, err := os.Create(filepath.Join(dir, "dump"))
	if err != nil {
		t.Fatal(err)
	}
	defer dump.Close()
	h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
	h.cli.RunMasked = func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error) {
		return mask.Run(mask.Command{Path: path, Args: argv, Env: env, Secrets: secrets, Stdout: dump, Stderr: dump})
	}
	h.cli.Die = mask.Die
	code := h.cli.Run([]string{"run", "--", "yes"})
	if code != 1 || !strings.Contains(h.err(), "keyward run: passing on the output of yes: ") || !strings.Contains(h.err(), "file too large") {
		t.Errorf("exit code = %d, stderr = %q", code, h.err())
	}
}

// After Run gives up on output a destination would not take, stderr may be that
// destination, and writing to it could block: run prints nothing, but records
// what it hid, and does not report success.
func TestRunPrintsNothingAfterTheOutputStalls(t *testing.T) {
	for _, exit := range []mask.Exit{
		{Masked: []string{"t"}, MidLine: true, Stalled: true},
		{Masked: []string{"t"}, Err: syscall.EIO, Stalled: true},
	} {
		h := newHarness(t, "", map[string]string{"t": token}, []string{"PATH=/usr/bin:/bin", "T=cap://t"})
		var events []activity.Event
		h.cli.Record = func(e activity.Event) { events = append(events, e) }
		withMasking(h, exit)
		code := h.cli.Run([]string{"run", "--", "printenv"})
		if code != 1 || h.err() != "" || !slices.ContainsFunc(events, func(e activity.Event) bool { return e.Operation == "mask" && e.Name == "t" }) {
			t.Errorf("%+v: exit code = %d, stderr = %q, events = %v", exit, code, h.err(), events)
		}
	}
}
