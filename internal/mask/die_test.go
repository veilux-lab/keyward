package mask

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
)

// die runs Die(sig) in a child process and returns how the child ended.
func die(t *testing.T, sig syscall.Signal) syscall.WaitStatus {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDieChild$")
	cmd.Env = append(os.Environ(), "KEYWARD_MASK_TEST_DIE="+strconv.Itoa(int(sig)))
	_ = cmd.Run()
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ws
}

func TestDieEndsTheProcessByTheSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGPIPE, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGXCPU} {
		if ws := die(t, sig); !ws.Signaled() || ws.Signal() != sig {
			t.Errorf("Die(%v) ended the process with %#x, want the signal", sig, ws)
		}
	}
}

// macOS files a crash report for a process a signal that dumps core ends, even
// with no core written, and keyward did not crash.
func TestDieExitsForASignalThatDumpsCore(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGQUIT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGABRT, syscall.SIGEMT, syscall.SIGFPE, syscall.SIGBUS, syscall.SIGSEGV, syscall.SIGSYS} {
		if ws := die(t, sig); !ws.Exited() || ws.ExitStatus() != 128+int(sig) {
			t.Errorf("Die(%v) ended the process with %#x, want exit status %d", sig, ws, 128+int(sig))
		}
	}
}

func TestDieChild(t *testing.T) {
	sig, err := strconv.Atoi(os.Getenv("KEYWARD_MASK_TEST_DIE"))
	if err != nil {
		t.Skip("subprocess helper")
	}
	Die(syscall.Signal(sig))
}
