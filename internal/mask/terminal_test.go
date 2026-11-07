package mask

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// These tests run keyward's side in the foreground of a new pseudo-terminal, as
// a shell runs a job, and type at it.

// openTerminal opens a pseudo-terminal as posix_openpt, grantpt, unlockpt and
// ptsname do on macOS, or skips the test. It returns the side that stands for
// the keyboard and screen, and the terminal, for the caller to close.
func openTerminal(t *testing.T) (keyboard, terminal *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	keyboard = os.NewFile(uintptr(fd), "/dev/ptmx")
	t.Cleanup(func() { keyboard.Close() })
	var name [128]byte
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		t.Skipf("no pseudo-terminal: %v", errno)
	}
	// Not os.OpenFile, which would watch it with kqueue: macOS then holds up the
	// exit of the terminal's session leader until it is closed.
	path := unix.ByteSliceToString(name[:])
	if fd, err = unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0); err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	return keyboard, os.NewFile(uintptr(fd), path)
}

// inTerminal starts leader, TestTerminalKeyward or TestTerminalParent, in a new
// terminal's foreground, running TestTerminalCommand as mode. It returns the
// keyboard, the command's stdout, and a wait for leader to end well.
func inTerminal(t *testing.T, leader, mode string) (keyboard, out *os.File, wait func()) {
	t.Helper()
	keyboard, terminal := openTerminal(t)
	// keyward's side has its own copy once started.
	defer terminal.Close()
	out = file(t, "out", "")
	var logs bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^"+leader+"$")
	cmd.Env = append(os.Environ(), "KEYWARD_MASK_TEST_OUT="+out.Name(), "KEYWARD_MASK_TEST_COMMAND="+mode)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = terminal, &logs, &logs
	// A session of its own, with the terminal as its controlling one, puts it in
	// the terminal's foreground.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Read what the terminal shows, as a screen would: its session leader cannot
	// exit while output, like an echoed ^C, waits there.
	go func() { _, _ = io.Copy(io.Discard, keyboard) }()
	var err error
	exited := make(chan struct{})
	go func() { err = cmd.Wait(); close(exited) }()
	// Ending keyward's side ends its session, which sends the command SIGHUP.
	stop := func() bool {
		_ = cmd.Process.Kill()
		select {
		case <-exited:
			return true
		case <-time.After(10 * time.Second):
			return false
		}
	}
	t.Cleanup(func() {
		if !stop() {
			t.Error("keyward's side could not be stopped")
		}
	})
	return keyboard, out, func() {
		t.Helper()
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			if stop() {
				t.Fatalf("keyward's side did not end\n%s", logs.String())
			}
			t.Fatal("keyward's side did not end")
		}
		if err != nil {
			t.Fatalf("keyward's side: %v\n%s", err, logs.String())
		}
	}
}

func TestRunGivesTheCommandItsTerminal(t *testing.T) {
	_, out, wait := inTerminal(t, "TestTerminalKeyward", "streams")
	wait()
	if got := contents(t, out); !strings.HasPrefix(got, "stdin true, stdout false, stderr true\n") {
		t.Errorf("the command saw %q, want its terminal as stdin and stderr", got)
	}
}

// The terminal sends Ctrl-C to its whole foreground, the command included, so
// keyward must not pass on its own copy.
func TestRunLetsCtrlCReachTheCommandOnce(t *testing.T) {
	keyboard, out, wait := inTerminal(t, "TestTerminalKeyward", "interrupts")
	until(t, "the command to start", func() bool { return strings.Contains(contents(t, out), "ready\n") })
	if _, err := keyboard.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	until(t, "the interrupt", func() bool { return strings.Contains(contents(t, out), "interrupt 1\n") })
	// One passed on as well would arrive within milliseconds.
	time.Sleep(time.Second)
	if strings.Contains(contents(t, out), "interrupt 2") {
		t.Fatal("one Ctrl-C reached the command twice")
	}
	if _, err := keyboard.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	wait()
}

// A command that puts itself in a process group of its own, as timeout does,
// leaves the terminal's foreground, which then sends Ctrl-C and Ctrl-\ to
// keyward alone, so keyward must pass them on.
func TestRunPassesKeyboardSignalsToACommandInAGroupOfItsOwn(t *testing.T) {
	keyboard, out, wait := inTerminal(t, "TestTerminalKeyward", "own group")
	until(t, "the command to start", func() bool { return strings.Contains(contents(t, out), "ready\n") })
	for _, key := range []struct {
		key  byte
		want string
	}{{0x03, "got interrupt\n"}, {0x1c, "got quit\n"}} {
		if _, err := keyboard.Write([]byte{key.key}); err != nil {
			t.Fatal(err)
		}
		until(t, key.want, func() bool { return strings.Contains(contents(t, out), key.want) })
	}
	wait()
}

// A script in keyward's process group, as a job a shell runs, may stop keyward
// with kill. That SIGINT reaches keyward alone, so keyward must pass it on.
func TestRunPassesOnAnInterruptSentWithKill(t *testing.T) {
	keyboard, out, wait := inTerminal(t, "TestTerminalParent", "interrupts")
	until(t, "the interrupt", func() bool { return strings.Contains(contents(t, out), "interrupt 1\n") })
	// The command ends at its second.
	if _, err := keyboard.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	wait()
}

// A session's first open of /dev/tty after its terminal hangs up, as when the
// window closes, waits for the terminal to come back, which it never does.
func TestForegroundAnswersAfterTheTerminalHangsUp(t *testing.T) {
	keyboard, terminal := openTerminal(t)
	out := file(t, "out", "")
	var logs bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestTerminalHangup$")
	cmd.Env = append(os.Environ(), "KEYWARD_MASK_TEST_OUT="+out.Name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = terminal, &logs, &logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	err := cmd.Start()
	terminal.Close()
	if err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	until(t, "the leader to start", func() bool { return contents(t, out) == "ready\n" })
	// Nothing reads the screen, so this closes it at once, which hangs up.
	keyboard.Close()
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("the leader: %v\n%s", err, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the leader did not end")
	}
}

// TestTerminalHangup is keyward's side for
// TestForegroundAnswersAfterTheTerminalHangsUp, the leader of the terminal's
// session, which the hangup sends SIGHUP.
func TestTerminalHangup(t *testing.T) {
	out := os.Getenv("KEYWARD_MASK_TEST_OUT")
	if out == "" {
		t.Skip("subprocess helper")
	}
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	// Nothing opens /dev/tty before the hangup, since only the first open waits.
	if err := os.WriteFile(out, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hangup:
	case <-time.After(10 * time.Second):
		t.Fatal("the terminal did not hang up")
	}
	answered := make(chan bool, 1)
	go func() { answered <- foreground() }()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("foreground waited for the terminal")
	}
}

// TestTerminalParent is a script that starts keyward's side and, once the
// command is ready, sends it SIGINT.
func TestTerminalParent(t *testing.T) {
	out := os.Getenv("KEYWARD_MASK_TEST_OUT")
	if out == "" {
		t.Skip("subprocess helper")
	}
	// A Ctrl-C reaches the script too, which it outlives.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGINT)
	child := exec.Command(os.Args[0], "-test.run=^TestTerminalKeyward$")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	until(t, "the command to start", func() bool {
		b, _ := os.ReadFile(out)
		return strings.Contains(string(b), "ready\n")
	})
	if err := child.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
}

// TestTerminalKeyward is keyward's side. Its stdin is the terminal, open for
// writing too, as a shell leaves it; Run gives that to the command as stdin and
// stderr, and its stdout goes to a file.
func TestTerminalKeyward(t *testing.T) {
	out := os.Getenv("KEYWARD_MASK_TEST_OUT")
	if out == "" {
		t.Skip("subprocess helper")
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	exit, err := Run(Command{
		Path: os.Args[0], Args: []string{os.Args[0], "-test.run=^TestTerminalCommand$"},
		Env: os.Environ(), Secrets: one("s", secret),
		Stdin: os.Stdin, Stdout: f, Stderr: os.Stdin,
	})
	if err != nil || exit.Code != 0 {
		t.Fatalf("Run: %+v, %v", exit, err)
	}
}

// TestTerminalCommand is the command keyward's side runs.
func TestTerminalCommand(t *testing.T) {
	switch os.Getenv("KEYWARD_MASK_TEST_COMMAND") {
	case "streams":
		fmt.Printf("stdin %v, stdout %v, stderr %v\n", term.IsTerminal(0), term.IsTerminal(1), term.IsTerminal(2))
	case "interrupts":
		interrupts := make(chan os.Signal, 2)
		signal.Notify(interrupts, syscall.SIGINT)
		fmt.Println("ready")
		for n := 1; n <= 2; n++ {
			<-interrupts
			fmt.Println("interrupt", n)
		}
	case "own group":
		// As timeout does, unless given --foreground. Out of the foreground, it gets
		// no hangup when the terminal goes, so it ends when its parent does.
		if err := syscall.Setpgid(0, 0); err != nil {
			t.Fatal(err)
		}
		go func() {
			for parent := os.Getppid(); os.Getppid() == parent; time.Sleep(100 * time.Millisecond) {
			}
			os.Exit(1)
		}()
		keys := make(chan os.Signal, 2)
		signal.Notify(keys, syscall.SIGINT, syscall.SIGQUIT)
		fmt.Println("ready")
		for range 2 {
			fmt.Println("got", <-keys)
		}
	default:
		t.Skip("subprocess helper")
	}
}
