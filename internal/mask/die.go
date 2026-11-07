package mask

/*
#include <signal.h>
#include <string.h>
#include <sys/resource.h>

// kw_die ends the process by sig, as its default action does. Should that dump
// core after all, the core would hold every value keyward resolved, so none is
// written.
static void kw_die(int sig) {
	struct rlimit none = {0, 0};
	setrlimit(RLIMIT_CORE, &none);
	struct sigaction dfl;
	memset(&dfl, 0, sizeof dfl);
	dfl.sa_handler = SIG_DFL;
	sigaction(sig, &dfl, NULL);
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, sig);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);
	raise(sig);
}
*/
import "C"

import (
	"os"
	"slices"
	"syscall"
)

// Die ends this process by the signal that ended the command, so whatever
// started keyward sees the same wait status. Go's runtime handles most signals
// itself, ending the process another way or not at all, so C raises it. For a
// signal that dumps core, macOS would file a crash report for keyward, which did
// not crash, so it exits with 128 plus the number instead, as a shell reports it.
func Die(sig syscall.Signal) {
	if !slices.Contains(dumpCore, sig) {
		C.kw_die(C.int(sig))
	}
	// Only such a signal, or one whose default action does not end a process,
	// gets here.
	os.Exit(128 + int(sig))
}

// dumpCore are the signals whose default action on macOS dumps core.
var dumpCore = []syscall.Signal{syscall.SIGQUIT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGABRT, syscall.SIGEMT, syscall.SIGFPE, syscall.SIGBUS, syscall.SIGSEGV, syscall.SIGSYS}
