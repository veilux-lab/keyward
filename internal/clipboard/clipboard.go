// Package clipboard puts a value on the macOS clipboard for keyward copy, and
// clears it again.
package clipboard

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// ClearArg, as the first argument, makes keyward the process ClearLater starts.
// main takes it before the CLI, so it is in no help or log and never reaches the
// daemon.
const ClearArg = "__clear-clipboard"

// Pasteboard is the clipboard as clearing it needs it. Its change count moves on
// each time anything is copied.
type Pasteboard interface {
	ChangeCount() int
	Clear()
}

// ClearLater starts keyward again to clear the clipboard after a delay, so the
// command that copied can exit.
func ClearLater(count int, after time.Duration) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := clearCommand(executable, count, after)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// clearCommand passes the change count and the delay, never the value. A session
// of its own, with no stdio, keeps it running when the terminal closes.
func clearCommand(executable string, count int, after time.Duration) *exec.Cmd {
	cmd := exec.Command(executable, ClearArg, strconv.Itoa(count), after.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

// ClearWhenDue is that process, given the arguments after ClearArg. It waits,
// then clears pb only if nothing was copied since, so it never takes away what
// the user copied next.
func ClearWhenDue(pb Pasteboard, args []string) {
	if len(args) != 2 {
		return
	}
	count, countErr := strconv.Atoi(args[0])
	after, afterErr := time.ParseDuration(args[1])
	if countErr != nil || afterErr != nil {
		return
	}
	time.Sleep(after)
	if pb.ChangeCount() == count {
		pb.Clear()
	}
}
