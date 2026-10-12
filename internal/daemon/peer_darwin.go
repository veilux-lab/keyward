//go:build darwin

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// sameUser admits only connections from the daemon's own user, read from the
// socket's peer credentials rather than anything the client claims.
func sameUser(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a Unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return fmt.Errorf("reading peer credentials: %w", credErr)
	}
	if int(cred.Uid) != os.Getuid() {
		return fmt.Errorf("peer uid %d is not the daemon's uid %d", cred.Uid, os.Getuid())
	}
	return nil
}
