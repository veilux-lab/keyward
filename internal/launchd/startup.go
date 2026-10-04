package launchd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"golang.org/x/sys/unix"
)

const homebrewLabel = "com.veilux-lab.keyward.homebrew"
const homebrewFormula = "veilux-lab/keyward/keyward"

type startupState struct {
	root *os.Root
	lock *os.File
}

func startupTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 5 * time.Second
	}
	return timeout
}

func privateStartupInfo(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0o700
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && stat.Nlink == 1
}

func lockStartup(home string, timeout time.Duration) (*startupState, error) {
	dir := filepath.Dir(daemon.DefaultSocket(home))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errors.New("could not create private startup directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !privateStartupInfo(info, true) {
		return nil, errors.New("startup directory must be owned by you and mode 700; symlinks are refused")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("could not open startup directory")
	}
	s := &startupState{root: root}
	opened, err := root.Stat(".")
	if err != nil || !privateStartupInfo(opened, true) || !os.SameFile(info, opened) {
		root.Close()
		return nil, errors.New("startup directory changed")
	}
	s.lock, err = s.file("startup.lock", true)
	if err != nil {
		root.Close()
		return nil, err
	}
	deadline := time.Now().Add(startupTimeout(timeout))
	for {
		err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			s.close()
			return nil, errors.New("could not acquire startup lock")
		}
		if time.Now().After(deadline) {
			s.close()
			return nil, errors.New("timed out waiting for startup lock; another service operation may be in progress")
		}
		time.Sleep(min(10*time.Millisecond, time.Until(deadline)))
	}
}

func (s *startupState) file(name string, create bool) (*os.File, error) {
	dir, err := s.root.Open(".")
	if err != nil {
		return nil, errors.New("could not open startup directory descriptor")
	}
	defer dir.Close()
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	var fd int
	if create {
		fd, err = unix.Openat(int(dir.Fd()), name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(int(dir.Fd()), name, flags, 0)
		}
	} else {
		fd, err = unix.Openat(int(dir.Fd()), name, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("could not safely open startup state: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil || !privateStartupInfo(info, false) {
		f.Close()
		return nil, errors.New("startup files must be regular, owned by you, and mode 600")
	}
	return f, nil
}

func (s *startupState) disabled() (bool, error) {
	f, err := s.file("startup.disabled", false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, f.Close()
}

func (s *startupState) disable() error {
	f, err := s.file("startup.disabled", true)
	if err != nil {
		return err
	}
	return f.Close()
}

func (s *startupState) enable() error {
	disabled, err := s.disabled()
	if err != nil || !disabled {
		return err
	}
	return s.root.Remove("startup.disabled")
}

func (s *startupState) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	s.root.Close()
}

var errStartupDisabled = errors.New("automatic startup is disabled; enable it with `keyward service install`")

func (m Manager) waitReady() error {
	deadline := time.Now().Add(startupTimeout(m.StartupTimeout))
	for {
		err := m.ready()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(min(25*time.Millisecond, time.Until(deadline)))
	}
}
