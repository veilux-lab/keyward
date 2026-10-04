package daemon

import (
	"io/fs"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestOnlyMissingListenerErrorsPermitStartup(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"absent", syscall.ENOENT, true},
		{"refused", syscall.ECONNREFUSED, true},
		{"permission", syscall.EACCES, false},
		{"timeout", syscall.ETIMEDOUT, false},
		{"deadline", os.ErrDeadlineExceeded, false},
		{"not a directory", syscall.ENOTDIR, false},
		{"generic missing file", fs.ErrNotExist, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &net.OpError{Op: "dial", Net: "unix", Err: &os.SyscallError{Syscall: "connect", Err: tc.err}}
			if got := notRunning(err); got != tc.want {
				t.Errorf("startup allowed = %t, want %t for %v", got, tc.want, err)
			}
		})
	}
}
