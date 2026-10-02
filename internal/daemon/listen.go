package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// DefaultSocket returns where the daemon listens unless KEYWARD_SOCKET says
// otherwise.
func DefaultSocket(home string) string {
	return filepath.Join(home, "Library", "Application Support", "keyward", "daemon.sock")
}

// Listen binds the socket at path, owning it for as long as the listener is open.
//
// A lock file beside the socket makes the daemon single-instance, which is also
// what makes an existing socket safe to delete: holding the lock proves no other
// daemon is serving it, so the socket is a leftover from one that crashed.
func Listen(path string) (net.Listener, error) {
	return listen(path)
}

func listen(path string) (*listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Refuse rather than chmod: the path may be user-supplied, and tightening a
	// shared directory would break whatever else uses it.
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible to other users; put the socket in a private directory", dir)
	}

	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("a keyward daemon is already running on %s", path)
		}
		return nil, err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		lock.Close()
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		lock.Close()
		return nil, err
	}
	return &listener{Listener: l, path: path, lock: lock}, nil
}

type listener struct {
	net.Listener
	path string
	lock *os.File
	once sync.Once
}

// Keep the instance lock until Run finishes draining requests.
func (l *listener) stopAccepting() {
	l.Listener.Close()
}

// Close removes the socket before releasing the lock, so it can never delete a
// socket that a newer daemon has just created.
func (l *listener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.Listener.Close()
		os.Remove(l.path)
		l.lock.Close()
	})
	return err
}
