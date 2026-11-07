package mask

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// secret is fake.
const secret = "FakeRunSecretValue0123456789"

// These tests run real commands. Run catches signals for the whole process, so
// none of them runs in parallel.

func file(t *testing.T, name, content string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func contents(t *testing.T, f *os.File) string {
	t.Helper()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

// sh runs script with sh, the secret in $S, and returns how it ended.
func sh(t *testing.T, script string, stdin, stdout, stderr *os.File, env ...string) Exit {
	t.Helper()
	exit, err := Run(Command{
		Path: "/bin/sh", Args: []string{"sh", "-c", script},
		Env:     append([]string{"S=" + secret, "PATH=/usr/bin:/bin"}, env...),
		Secrets: one("s", secret),
		Stdin:   stdin, Stdout: stdout, Stderr: stderr,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return exit
}

// background runs sh in a goroutine, for a test that signals or reads it while
// it runs, and fails the test if it does not end in time.
func background(t *testing.T, script string, stdout, stderr *os.File) func() Exit {
	t.Helper()
	done := make(chan Exit, 1)
	go func() { done <- sh(t, script, file(t, "in", ""), stdout, stderr) }()
	return func() Exit {
		select {
		case exit := <-done:
			return exit
		case <-time.After(10 * time.Second):
			t.Fatal("the command did not end")
			return Exit{}
		}
	}
}

func signalSelf(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
}

func readLine(t *testing.T, r *bufio.Reader, want string) {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil || line != want {
		t.Fatalf("read %q, %v; want %q", line, err, want)
	}
}

// fill writes to w until its pipe is full, so that a write waits for a reader.
func fill(t *testing.T, w *os.File) {
	t.Helper()
	chunk := make([]byte, 64<<10)
	_ = w.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		if _, err := w.Write(chunk); errors.Is(err, os.ErrDeadlineExceeded) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	_ = w.SetWriteDeadline(time.Time{})
}

// stopWaiting sends SIGTERM until Run returns on done. One may reach the command
// instead, when Run has not yet seen it end.
func stopWaiting(t *testing.T, done <-chan Exit) Exit {
	t.Helper()
	// Caught here too, a SIGTERM that arrives as Run returns does not end the test.
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, syscall.SIGTERM)
	defer signal.Stop(caught)
	for range 10 {
		signalSelf(t, syscall.SIGTERM)
		<-caught
		select {
		case exit := <-done:
			return exit
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatal("Run did not stop waiting")
	return Exit{}
}

// until waits for ok, and fails the test if it does not come in time.
func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func setForeground(t *testing.T, in bool) {
	t.Helper()
	saved := foreground
	foreground = func() bool { return in }
	t.Cleanup(func() { foreground = saved })
}

func TestRunHidesTheSecretInBothStreams(t *testing.T) {
	out, errs := file(t, "out", ""), file(t, "err", "")
	exit := sh(t, `printf 'out %s\n' "$S"; printf 'err %s\n' "$S" >&2`, file(t, "in", ""), out, errs)
	if got := contents(t, out); got != "out cap://s#masked\n" {
		t.Errorf("stdout = %q", got)
	}
	if got := contents(t, errs); got != "err cap://s#masked\n" {
		t.Errorf("stderr = %q", got)
	}
	if exit.Code != 0 || exit.Signal != 0 || !slices.Equal(exit.Masked, []string{"s"}) || exit.MidLine || exit.Err != nil {
		t.Errorf("exit = %+v", exit)
	}
}

func TestRunHidesWhatPrintenvShows(t *testing.T) {
	out := file(t, "out", "")
	_, err := Run(Command{Path: "/usr/bin/printenv", Args: []string{"printenv"}, Env: []string{"S=" + secret},
		Secrets: one("s", secret), Stdout: out, Stderr: out})
	if got := contents(t, out); err != nil || got != "S=cap://s#masked\n" {
		t.Errorf("printenv showed %q, %v", got, err)
	}
}

// Any program can read the environment's other values, so what one holds of a
// secret, like a stored file in JSON or the secret URL-encoded, is not hidden,
// as Select leaves out a whole value found there.
func TestRunLeavesAloneWhatThePlainEnvironmentHolds(t *testing.T) {
	creds, password := "[fake]\ntoken = FakeLineToken0123456789\n", "Fake@Passw0rd:2026"
	credsJSON, _ := json.Marshal(map[string]string{"creds": creds})
	dbURL := "postgres://app:Fake%40Passw0rd%3A2026@db/app"
	out := file(t, "out", "")
	exit, err := Run(Command{
		Path: "/bin/sh", Args: []string{"sh", "-c", `printf '%s\n' "$CREDS_JSON" "$DATABASE_URL"; printf '%s' "$CREDS"`},
		Env:     []string{"PATH=/usr/bin:/bin", "CREDS=" + creds, "PASSWORD=" + password, "CREDS_JSON=" + string(credsJSON), "DATABASE_URL=" + dbURL},
		Secrets: []Secret{{Name: "creds", Value: creds}, {Name: "pw", Value: password}},
		Stdout:  out, Stderr: out,
	})
	want := string(credsJSON) + "\n" + dbURL + "\n" + Placeholder("creds") + "\n"
	if got := contents(t, out); err != nil || got != want || !slices.Equal(exit.Masked, []string{"creds"}) {
		t.Errorf("output = %q, exit = %+v, %v; want %q", got, exit, err, want)
	}
}

func TestRunKeepsTheOrderOfStreamsSharingAFile(t *testing.T) {
	both := file(t, "both", "")
	sh(t, `for i in 1 2 3 4 5; do echo "out $i"; echo "err $i $S" >&2; done`, file(t, "in", ""), both, both)
	var want strings.Builder
	for _, i := range "12345" {
		want.WriteString("out " + string(i) + "\nerr " + string(i) + " cap://s#masked\n")
	}
	if got := contents(t, both); got != want.String() {
		t.Errorf("output = %q, want %q", got, want.String())
	}
}

func TestRunKeepsTheOrderOfStreamsSharingAPipe(t *testing.T) {
	r, w := pipe(t)
	read := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); read <- string(b) }()
	sh(t, `echo one; echo two >&2; echo three`, file(t, "in", ""), w, w)
	w.Close()
	if got := <-read; got != "one\ntwo\nthree\n" {
		t.Errorf("output = %q", got)
	}
}

func TestRunReturnsTheExitCode(t *testing.T) {
	if exit := sh(t, "exit 7", nil, nil, nil); exit.Code != 7 || exit.Signal != 0 {
		t.Errorf("exit = %+v, want code 7", exit)
	}
}

func TestRunReportsTheSignalThatEndedTheCommand(t *testing.T) {
	out := file(t, "out", "")
	if exit := sh(t, "kill -TERM $$", nil, out, out); exit.Signal != syscall.SIGTERM || exit.Code != 128+15 {
		t.Errorf("exit = %+v, want SIGTERM", exit)
	}
}

func TestRunGivesTheCommandItsInput(t *testing.T) {
	out := file(t, "out", "")
	sh(t, `read x; printf '%s|\n' "$x"`, file(t, "in", "line one\n"), out, out)
	if got := contents(t, out); got != "line one|\n" {
		t.Errorf("output = %q", got)
	}
}

func TestRunGivesTheCommandAClosedStreamClosed(t *testing.T) {
	closed, errs := file(t, "closed", ""), file(t, "err", "")
	closed.Close()
	// Nothing opens a file before the write, which would take the closed number.
	sh(t, `echo hi; echo "status $?" >&2`, file(t, "in", ""), closed, errs)
	if got := contents(t, errs); !strings.Contains(got, "Bad file descriptor") || !strings.HasSuffix(got, "status 1\n") {
		t.Errorf("stderr = %q, want a failed write", got)
	}
}

func TestRunEndsTheCommandWhenNothingReadsItsOutput(t *testing.T) {
	r, w := pipe(t)
	r.Close()
	wait := background(t, `while :; do echo "x $S"; done`, w, file(t, "err", ""))
	if exit := wait(); exit.Signal != syscall.SIGPIPE || exit.Err != nil {
		t.Errorf("exit = %+v, want SIGPIPE", exit)
	}
}

// A destination that fails other than by its reader going takes no more output,
// so Run closes the pipe, and SIGPIPE ends the command at its next write, even
// one that would go on past a failed write, as this loop would.
func TestRunStopsTheCommandWhenItsDestinationFails(t *testing.T) {
	readOnly, err := os.Open(file(t, "ro", "").Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	for _, script := range []string{"exec yes", `while :; do echo "x $S"; sleep 0.1; done`} {
		wait := background(t, script, readOnly, file(t, "err", ""))
		if exit := wait(); exit.Signal != syscall.SIGPIPE || !errors.Is(exit.Err, syscall.EBADF) {
			t.Errorf("%s: exit = %+v, want SIGPIPE and the failure reported", script, exit)
		}
	}
}

// When its destination fails, a command that ignores SIGPIPE, as Python does,
// or catches it, as Ruby does, gets EPIPE at its next write instead, and may go
// on.
func TestRunLetsACommandThatIgnoresOrCatchesSIGPIPEGoOn(t *testing.T) {
	readOnly, err := os.Open(file(t, "ro", "").Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	for _, trap := range []string{`trap '' PIPE`, `trap 'echo caught >&2' PIPE`} {
		errs := file(t, "err", "")
		wait := background(t, trap+`; while echo "x $S"; do sleep 0.05; done; echo went on >&2`, readOnly, errs)
		if exit := wait(); exit.Signal != 0 || exit.Code != 0 || !errors.Is(exit.Err, syscall.EBADF) || !strings.HasSuffix(contents(t, errs), "went on\n") {
			t.Errorf("%s: exit = %+v, stderr = %q; want the command to go on", trap, exit, contents(t, errs))
		}
	}
}

func TestRunWaitsForOutputTheCommandLeftRunning(t *testing.T) {
	out := file(t, "out", "")
	sh(t, `(sleep 0.3; printf 'late %s\n' "$S") & echo early`, nil, out, out)
	if got := contents(t, out); got != "early\nlate cap://s#masked\n" {
		t.Errorf("output = %q", got)
	}
}

func TestRunStopsWaitingForLeftoverOutputOnASignal(t *testing.T) {
	out, errs := file(t, "out", ""), file(t, "err", "")
	done := make(chan Exit, 1)
	go func() { done <- sh(t, `trap '' TERM; sleep 5 & echo early; echo ended >&2`, nil, out, errs) }()
	until(t, "the command to end", func() bool { return contents(t, errs) == "ended\n" })
	exit := stopWaiting(t, done)
	if got := contents(t, out); got != "early\n" || exit.Code != 0 || exit.Stalled {
		t.Errorf("output = %q, exit = %+v", got, exit)
	}
}

func TestRunStopsWaitingForADestinationThatTakesNoMore(t *testing.T) {
	_, w := pipe(t)
	fill(t, w)
	errs := file(t, "err", "")
	done := make(chan Exit, 1)
	go func() { done <- sh(t, `trap '' TERM; echo "x $S"; echo ended >&2`, nil, w, errs) }()
	until(t, "the command to end", func() bool { return contents(t, errs) == "ended\n" })
	select {
	case exit := <-done:
		t.Fatalf("Run returned %+v before a signal said to stop waiting", exit)
	case <-time.After(300 * time.Millisecond):
	}
	exit := stopWaiting(t, done)
	if !exit.Stalled || exit.Code != 0 || exit.Err != nil || !slices.Equal(exit.Masked, []string{"s"}) {
		t.Errorf("exit = %+v, want it stalled with the secret named", exit)
	}
}

// One terminating signal is enough, as it is without keyward: once the command
// has ended by it, Run stops waiting for what the command left running.
func TestRunStopsWaitingForLeftoverOutputAfterOneSignal(t *testing.T) {
	out, errs := file(t, "out", ""), file(t, "err", "")
	wait := background(t, `sleep 30 & echo $! >&2; wait`, out, errs)
	until(t, "the command to start", func() bool { return strings.HasSuffix(contents(t, errs), "\n") })
	if left, err := strconv.Atoi(strings.TrimSpace(contents(t, errs))); err == nil {
		t.Cleanup(func() { _ = syscall.Kill(left, syscall.SIGKILL) })
	}
	signalSelf(t, syscall.SIGTERM)
	if exit := wait(); exit.Signal != syscall.SIGTERM || exit.Stalled {
		t.Errorf("exit = %+v, want SIGTERM", exit)
	}
}

// The same holds for a destination that takes no more output.
func TestRunStopsWaitingForADestinationThatTakesNoMoreAfterOneSignal(t *testing.T) {
	_, w := pipe(t)
	fill(t, w)
	errs := file(t, "err", "")
	wait := background(t, `echo ready >&2; while :; do echo "x $S"; done`, w, errs)
	until(t, "the command to start", func() bool { return contents(t, errs) == "ready\n" })
	signalSelf(t, syscall.SIGTERM)
	if exit := wait(); exit.Signal != syscall.SIGTERM || !exit.Stalled {
		t.Errorf("exit = %+v, want SIGTERM, and it stalled", exit)
	}
}

// What the command wrote before it ended still gets out, even to a destination
// that takes it only after the command has ended.
func TestRunPassesOnTheLastOutputAfterOneSignal(t *testing.T) {
	r, w := pipe(t)
	fill(t, w)
	er, ew := pipe(t)
	errs := bufio.NewReader(er)
	last := strings.Repeat("y", 40<<10)
	done := make(chan Exit, 1)
	go func() {
		done <- sh(t, `trap 'printf "%s %s\n" "$LAST" "$S"; echo ended >&2; exit 0' TERM; echo ready >&2; while :; do sleep 0.1; done`,
			nil, w, ew, "LAST="+last)
	}()
	readLine(t, errs, "ready\n")
	signalSelf(t, syscall.SIGTERM)
	readLine(t, errs, "ended\n")
	read := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); read <- string(b) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	w.Close()
	if got := <-read; !strings.HasSuffix(got, last+" cap://s#masked\n") {
		t.Errorf("the output ends %q, want the command's last line", got[max(0, len(got)-40):])
	}
}

// A signal that comes once the command has ended, as when one reaches the
// command first, stops the wait for anything it left running, but what it wrote
// before it ended still gets out.
func TestRunPassesOnTheLastOutputWhenASignalComesAfterTheEnd(t *testing.T) {
	r, w := pipe(t)
	fill(t, w)
	er, ew := pipe(t)
	last := strings.Repeat("y", 40<<10)
	done := make(chan Exit, 1)
	go func() {
		done <- sh(t, `trap 'printf "%s %s\n" "$LAST" "$S"; exit 0' TERM; echo $$ >&2; while :; do sleep 0.1; done`,
			nil, w, ew, "LAST="+last)
	}()
	line, err := bufio.NewReader(er).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	// Its last line waits for the destination to take more.
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	until(t, "the command to end", func() bool { return syscall.Kill(pid, 0) != nil })
	// Caught here too, a SIGTERM that arrives as Run returns does not end the test.
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, syscall.SIGTERM)
	defer signal.Stop(caught)
	// Run sees the end, and then the signal, before anything reads the output.
	time.Sleep(100 * time.Millisecond)
	signalSelf(t, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	read := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); read <- string(b) }()
	var exit Exit
	select {
	case exit = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	w.Close()
	if got := <-read; exit.Stalled || !strings.HasSuffix(got, last+" cap://s#masked\n") {
		t.Errorf("exit = %+v; the output ends %q, want the command's last line", exit, got[max(0, len(got)-40):])
	}
}

// After Run gives up, its copier still waits to write to keyward's stdout. If
// the reader goes then, that write must fail, not end keyward by SIGPIPE before
// it says how the command ended.
func TestAStalledWriteFailsWhenItsReaderGoes(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^TestStalledWriteChild$", "-test.v")
	child.Env = append(os.Environ(), "KEYWARD_MASK_TEST_STALLED=1")
	if out, err := child.CombinedOutput(); err != nil || !strings.Contains(string(out), "--- PASS: TestStalledWriteChild") {
		t.Errorf("%v\n%s", err, out)
	}
}

// TestStalledWriteChild is keyward for TestAStalledWriteFailsWhenItsReaderGoes,
// with a stdout it fills and stops reading. Only on fd 1 or 2 does Go end a
// program by SIGPIPE.
func TestStalledWriteChild(t *testing.T) {
	if os.Getenv("KEYWARD_MASK_TEST_STALLED") == "" {
		t.Skip("subprocess helper")
	}
	saved, err := unix.Dup(1)
	if err != nil {
		t.Fatal(err)
	}
	// Put back for the test's own report.
	t.Cleanup(func() { _ = unix.Dup2(saved, 1) })
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(p[1], 1); err != nil {
		t.Fatal(err)
	}
	unix.Close(p[1])
	_ = unix.SetNonblock(1, true)
	for chunk := make([]byte, 64<<10); ; {
		if _, err := unix.Write(1, chunk); err != nil {
			break
		}
	}
	_ = unix.SetNonblock(1, false)

	errs := file(t, "err", "")
	done := make(chan Exit, 1)
	go func() { done <- sh(t, `trap '' TERM; echo "x $S"; echo ended >&2`, nil, os.Stdout, errs) }()
	until(t, "the command to end", func() bool { return contents(t, errs) == "ended\n" })
	if exit := stopWaiting(t, done); !exit.Stalled {
		t.Fatalf("exit = %+v, want it stalled", exit)
	}
	unix.Close(p[0])
	// The copier's write fails now, and this one does for certain.
	if _, err := os.Stdout.Write([]byte("x")); !errors.Is(err, syscall.EPIPE) {
		t.Errorf("writing with the reader gone: %v", err)
	}
}

func TestRunLetsAHeldStartGoAfterAQuietMoment(t *testing.T) {
	r, w := pipe(t)
	done := make(chan Exit, 1)
	go func() { done <- sh(t, `printf 'x %s' "$P"; sleep 1; echo`, nil, w, w, "P="+secret[:3]) }()
	_ = r.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(r, buf, 5)
	if got := string(buf[:n]); err != nil || got != "x "+secret[:3] {
		t.Errorf("before the command went on, read %q, %v", got, err)
	}
	<-done
}

func TestRunSaysWhenStderrEndsMidLine(t *testing.T) {
	errs := file(t, "err", "")
	exit := sh(t, `printf 'Enter host password for user %s:' "$S" >&2`, nil, file(t, "out", ""), errs)
	if got := contents(t, errs); got != "Enter host password for user cap://s#masked:" || !exit.MidLine {
		t.Errorf("stderr = %q, exit = %+v", got, exit)
	}
}

func TestRunPassesOnATerminatingSignal(t *testing.T) {
	r, w := pipe(t)
	wait := background(t, "echo ready; exec sleep 10", w, file(t, "err", ""))
	readLine(t, bufio.NewReader(r), "ready\n")
	signalSelf(t, syscall.SIGTERM)
	if exit := wait(); exit.Signal != syscall.SIGTERM {
		t.Errorf("exit = %+v, want SIGTERM", exit)
	}
}

// A timer's or a limit's signal, as perl -e 'alarm shift; exec @ARGV' sends,
// is passed on too: Go drops one that nothing asked for.
func TestRunPassesOnATimersSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGALRM, syscall.SIGVTALRM, syscall.SIGXCPU} {
		r, w := pipe(t)
		wait := background(t, "echo ready; exec sleep 5", w, file(t, "err", ""))
		readLine(t, bufio.NewReader(r), "ready\n")
		signalSelf(t, sig)
		if exit := wait(); exit.Signal != sig {
			t.Errorf("exit = %+v, want %v", exit, sig)
		}
	}
}

func TestRunPassesOnAnInterruptOutsideTheForeground(t *testing.T) {
	if signal.Ignored(syscall.SIGINT) {
		t.Skip("interrupts are ignored here, so the command ignores them too")
	}
	setForeground(t, false)
	r, w := pipe(t)
	wait := background(t, "echo ready; exec sleep 10", w, file(t, "err", ""))
	readLine(t, bufio.NewReader(r), "ready\n")
	signalSelf(t, syscall.SIGINT)
	if exit := wait(); exit.Signal != syscall.SIGINT {
		t.Errorf("exit = %+v, want SIGINT", exit)
	}
}

// interruptFromOutside sends this process SIGINT from a process in a session of
// its own that goes on running, as a typed Ctrl-C comes from whatever writes to
// the terminal.
func interruptFromOutside(t *testing.T) {
	t.Helper()
	sender := exec.Command("/bin/sh", "-c", `kill -INT "$1" && echo sent && exec sleep 10`, "sh", strconv.Itoa(os.Getpid()))
	sender.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := sender.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Process.Kill(); _ = sender.Wait() })
	readLine(t, bufio.NewReader(out), "sent\n")
}

// In the foreground of a terminal, the terminal sends Ctrl-C to the command
// itself; passing it on as well would make it seem pressed twice.
func TestRunLeavesAKeyboardInterruptToTheTerminal(t *testing.T) {
	if signal.Ignored(syscall.SIGINT) {
		t.Skip("interrupts are ignored here")
	}
	setForeground(t, true)
	r, w := pipe(t)
	wait := background(t, "echo ready; exec sleep 10", w, file(t, "err", ""))
	readLine(t, bufio.NewReader(r), "ready\n")
	interruptFromOutside(t)
	time.Sleep(200 * time.Millisecond)
	signalSelf(t, syscall.SIGTERM)
	if exit := wait(); exit.Signal != syscall.SIGTERM {
		t.Errorf("exit = %+v, want SIGTERM, the interrupt not passed on", exit)
	}
}

// A SIGINT from keyward's own session, as from a script that started keyward,
// did not come from the terminal, so it is passed on.
func TestRunPassesOnAnInterruptFromItsSession(t *testing.T) {
	if signal.Ignored(syscall.SIGINT) {
		t.Skip("interrupts are ignored here, so the command ignores them too")
	}
	setForeground(t, true)
	r, w := pipe(t)
	wait := background(t, "echo ready; exec sleep 30", w, file(t, "err", ""))
	readLine(t, bufio.NewReader(r), "ready\n")
	signalSelf(t, syscall.SIGINT)
	if exit := wait(); exit.Signal != syscall.SIGINT {
		t.Errorf("exit = %+v, want SIGINT", exit)
	}
}

func TestRunReportsACommandThatCannotStart(t *testing.T) {
	out := file(t, "out", "")
	if _, err := Run(Command{Path: "/nonexistent/command", Args: []string{"command"}, Stdout: out, Stderr: out}); err == nil {
		t.Error("Run started a command that does not exist")
	}
}
