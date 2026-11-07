package mask

/*
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static int kw_keys = -1;

// kw_key writes the signal and the pid that sent it, which only SA_SIGINFO
// gives, to kw_keys for Go to read.
static void kw_key(int sig, siginfo_t *info, void *context) {
	int saved = errno;
	int msg[2] = {sig, info->si_pid};
	(void)write(kw_keys, msg, sizeof msg);
	errno = saved;
}

// kw_catch catches sig with kw_key, which writes to fd, and keeps the action it
// replaces in old.
static int kw_catch(int sig, int fd, struct sigaction *old) {
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = kw_key;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigfillset(&sa.sa_mask);
	kw_keys = fd;
	return sigaction(sig, &sa, old);
}

static int kw_restore(int sig, struct sigaction *old) {
	return sigaction(sig, old, NULL);
}
*/
import "C"

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
	"syscall"
)

// sent is a signal and the pid of the process that sent it, or 0.
type sent struct {
	sig    syscall.Signal
	sender int
}

// catcher carries what kw_key writes. Its pipe stays open: a handler may still
// be writing to it as catchKeys puts the old action back.
var catcher struct {
	once sync.Once
	w    int
	c    chan sent
	err  error
}

// catchKeys catches sigs with the pid that sends each, which os/signal does not
// say, until restore puts back how they were handled.
func catchKeys(sigs []syscall.Signal) (c <-chan sent, restore func(), err error) {
	catcher.once.Do(func() {
		var p [2]int
		// As os.Pipe does, so no command started meanwhile gets the pipe.
		syscall.ForkLock.RLock()
		if catcher.err = syscall.Pipe(p[:]); catcher.err == nil {
			syscall.CloseOnExec(p[0])
			syscall.CloseOnExec(p[1])
		}
		syscall.ForkLock.RUnlock()
		if catcher.err != nil {
			return
		}
		// A full pipe loses a signal, rather than block its handler, and Go's poller
		// waits on the reading end.
		for _, fd := range p {
			if catcher.err = syscall.SetNonblock(fd, true); catcher.err != nil {
				return
			}
		}
		catcher.w, catcher.c = p[1], make(chan sent, 16)
		r := os.NewFile(uintptr(p[0]), "keys")
		go func() {
			var msg [8]byte
			for {
				if _, err := io.ReadFull(r, msg[:]); err != nil {
					return
				}
				sig, pid := int32(binary.NativeEndian.Uint32(msg[:4])), int32(binary.NativeEndian.Uint32(msg[4:]))
				catcher.c <- sent{syscall.Signal(sig), int(pid)}
			}
		}()
	})
	if catcher.err != nil {
		return nil, nil, catcher.err
	}
	// One caught as the last Run ended is not for this one.
	for len(catcher.c) > 0 {
		<-catcher.c
	}
	old := make([]C.struct_sigaction, len(sigs))
	caught := 0
	restore = func() {
		for i := range caught {
			C.kw_restore(C.int(sigs[i]), &old[i])
		}
	}
	for ; caught < len(sigs); caught++ {
		if r, err := C.kw_catch(C.int(sigs[caught]), C.int(catcher.w), &old[caught]); r != 0 {
			restore()
			return nil, nil, err
		}
	}
	return catcher.c, restore, nil
}
