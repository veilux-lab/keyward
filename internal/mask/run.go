package mask

import (
	"errors"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Command is a command for Run to start.
type Command struct {
	Path string
	// Args is the argument vector, the command's own name first.
	Args    []string
	Env     []string
	Secrets []Secret

	Stdin, Stdout, Stderr *os.File
}

// Exit is how a command that Run started ended.
type Exit struct {
	// Code is the command's exit status or, for a command a signal ended, 128 plus
	// the signal's number, as a shell reports it.
	Code   int
	Signal syscall.Signal
	// Masked names the secrets hidden at least once, sorted. The output may show
	// one under another's placeholder, as when its value is inside the other's.
	Masked []string
	// MidLine is true when the last output written to stderr's destination did
	// not end a line, so a message written after it should start a new one.
	MidLine bool
	// Err is the first failure writing the output, other than its reader having
	// gone away. Run closes that pipe then, so the command's next write fails.
	Err error
	// Stalled is true when Run stopped waiting for output it could not pass on: a
	// destination took no more after the command ended, and a signal said to stop.
	Stalled bool
}

// quiet is how long a held start of a secret waits for the rest of it before
// flush lets it go. Only a secret that spans lines, like a private key, can
// start with a whole line, so a protocol written a line at a time, like an MCP
// server's, is not held up.
const quiet = 50 * time.Millisecond

// stall is how long copiers get to pass on what they hold once a signal has said
// to stop waiting; when a signal ends the command, its last output gets as long
// again first. One still writing after that has a destination that takes no
// more output.
const stall = time.Second

// Run starts the command with each of its output streams that is not a
// terminal passed through a filter, waits for it, and returns how it ended.
// Standard input and terminals are the command's own. SIGTERM, SIGHUP, SIGINT,
// SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM, SIGVTALRM and SIGXCPU that keyward
// receives are passed on, except a SIGINT or SIGQUIT that may have been typed:
// one the terminal sent the command too, or, since it looks the same, one a
// live process in another session sent with kill. A stop, like SIGTSTP, stops
// keyward alone.
//
// Run returns once the command has ended and its output has been passed on,
// which also waits for anything it left running that still writes to it, the
// same as a shell pipeline does. A terminating signal stops that wait: at once
// if the command has ended, or else a while after it ends. Output written by
// then still goes out, unless its destination takes no more for a while.
func Run(c Command) (Exit, error) {
	files := []*os.File{open(c.Stdin), open(c.Stdout), open(c.Stderr)}
	pats := patterns(c.Secrets, others(c.Env, c.Secrets))
	var copiers []*copier
	var ends []*os.File
	// pass gives the command a pipe instead of stream i and filters what comes
	// out of it into the stream.
	pass := func(i int, toErr bool) error {
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		ends = append(ends, w)
		copiers = append(copiers, &copier{src: r, dst: files[i], f: filterFor(pats), toErr: toErr})
		files[i] = w
		return nil
	}
	outPiped := files[1] != nil && !term.IsTerminal(int(files[1].Fd()))
	errPiped := files[2] != nil && !term.IsTerminal(int(files[2].Fd()))
	var err error
	switch {
	case outPiped && errPiped && sameFile(files[1], files[2]):
		// One pipe keeps the order in which the command interleaves the two.
		if err = pass(1, true); err == nil {
			files[2] = files[1]
		}
	case outPiped && errPiped:
		if err = pass(1, false); err == nil {
			err = pass(2, true)
		}
	case outPiped:
		err = pass(1, false)
	case errPiped:
		err = pass(2, true)
	}
	if err != nil {
		closeAll(ends, copiers)
		return Exit{}, err
	}

	// Catch signals before starting, so none falls between start and relaying.
	// Go drops a timer's or a limit's signal that nothing asks for, so those are
	// asked for here, to be passed on. SIGXFSZ is not: keyward's own write to a
	// full file gets it, and Go dropping it makes that write fail instead. SIGPIPE
	// is caught too, so a write to a reader that has gone away fails rather than
	// ending keyward; the copier passes that on to the command. The keyboard's
	// are caught apart, with the pid that sent each.
	relayed := []os.Signal{syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGALRM, syscall.SIGVTALRM, syscall.SIGXCPU, syscall.SIGPIPE}
	keyboard := []syscall.Signal{syscall.SIGQUIT}
	// Ignored from the start, as under nohup or in a background job, these stay
	// ignored, for the command too.
	if !signal.Ignored(syscall.SIGHUP) {
		relayed = append(relayed, syscall.SIGHUP)
	}
	if !signal.Ignored(syscall.SIGINT) {
		keyboard = append(keyboard, syscall.SIGINT)
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, relayed...)
	defer signal.Stop(signals)
	keys, restore, err := catchKeys(keyboard)
	if err != nil {
		closeAll(ends, copiers)
		return Exit{}, err
	}
	defer restore()

	proc, err := os.StartProcess(c.Path, c.Args, &os.ProcAttr{Env: c.Env, Files: files})
	// The command has its own copies of the pipes; keyward closing its copies is
	// what lets the output end when the command's do.
	for _, w := range ends {
		w.Close()
	}
	if err != nil {
		closeAll(nil, copiers)
		return Exit{}, err
	}

	var wg sync.WaitGroup
	for _, cp := range copiers {
		wg.Go(cp.run)
	}
	copied := make(chan struct{})
	go func() {
		wg.Wait()
		close(copied)
	}()
	waited := make(chan *os.ProcessState, 1)
	go func() {
		state, _ := proc.Wait()
		waited <- state
	}()

	var state *os.ProcessState
	// stopping is set by a terminating signal that comes while the command runs.
	ended, stalled, stopping := false, false, false
	var grace, giveUp <-chan time.Time
	// stop stops waiting for output from anything the command left running, and
	// soon for a destination that takes no more, but what the pipes hold goes out.
	stop := func() {
		if giveUp == nil {
			for _, cp := range copiers {
				cp.stop()
			}
			giveUp = time.After(stall)
		}
	}
	// signalled passes sig on while the command runs, unless the terminal has
	// sent it the same one, and stops the wait for its output after.
	signalled := func(sig syscall.Signal, typed bool) {
		terminating := sig != syscall.SIGUSR1 && sig != syscall.SIGUSR2
		switch {
		case sig == syscall.SIGPIPE:
		case !ended:
			stopping = stopping || terminating
			if !typed {
				_ = proc.Signal(sig)
			}
		case terminating:
			// The command has ended, and only something it left running keeps its
			// output open.
			stop()
		}
	}
	for !stalled && (!ended || copied != nil) {
		select {
		case s := <-signals:
			signalled(s.(syscall.Signal), false)
		case k := <-keys:
			// A typed one reaches every process in the foreground, the command
			// included unless it has left keyward's process group, as timeout does;
			// sending it again would make it seem pressed twice. One sent with kill
			// by a live process in another session, as by pexpect, node-pty or a
			// shell in another terminal, looks the same, so it is dropped too.
			signalled(k.sig, fromTerminal(k.sender) && foreground() && inGroup(proc.Pid))
		case state = <-waited:
			ended = true
			if stopping {
				// What the command wrote before it ended has a while to get out.
				grace = time.After(stall)
			}
		case <-grace:
			stop()
		case <-copied:
			copied = nil
		case <-giveUp:
			// A copier still writing stays blocked until the process ends. SIGPIPE
			// stays caught, so its reader going fails that write, not keyward.
			signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
			stalled = true
		}
	}

	exit := Exit{Code: 1, Stalled: stalled}
	if state != nil {
		if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			exit.Signal = ws.Signal()
			exit.Code = 128 + int(exit.Signal)
		} else {
			exit.Code = state.ExitCode()
		}
	}
	for _, cp := range copiers {
		cp.mu.Lock()
		for name := range cp.f.masked {
			if !slices.Contains(exit.Masked, name) {
				exit.Masked = append(exit.Masked, name)
			}
		}
		if cp.toErr {
			exit.MidLine = cp.wrote && cp.last != '\n'
		}
		if exit.Err == nil {
			exit.Err = cp.err
		}
		cp.mu.Unlock()
	}
	slices.Sort(exit.Masked)
	return exit, nil
}

// foreground reports whether keyward is in the foreground of its terminal, which
// sends a keyboard signal to keyward's whole process group. The open does not
// wait for the terminal, which after a hangup never comes back. A variable so
// tests need no terminal.
var foreground = func() bool {
	tty, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(tty)
	group, err := unix.IoctlGetInt(tty, unix.TIOCGPGRP)
	return err == nil && group == unix.Getpgrp()
}

// fromTerminal reports whether a keyboard signal that pid sent may have been
// typed. The kernel sends those as no process, or as the one that writes to the
// terminal, which runs outside keyward's session, as Terminal, sshd and tmux do.
// A sender that has gone, like the kill command, did not type it.
func fromTerminal(pid int) bool {
	if pid == 0 {
		return true
	}
	session, err := unix.Getsid(pid)
	mine, _ := unix.Getsid(0)
	return err == nil && session != mine
}

// inGroup reports whether process pid is in keyward's process group.
func inGroup(pid int) bool {
	group, err := unix.Getpgid(pid)
	return err == nil && group == unix.Getpgrp()
}

// open returns f, or nil if it is not an open file, so the command gets that
// stream closed as keyward did.
func open(f *os.File) *os.File {
	if f == nil {
		return nil
	}
	if _, err := f.Stat(); err != nil {
		return nil
	}
	return f
}

func sameFile(a, b *os.File) bool {
	ia, errA := a.Stat()
	ib, errB := b.Stat()
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

func closeAll(ends []*os.File, copiers []*copier) {
	for _, w := range ends {
		w.Close()
	}
	for _, cp := range copiers {
		cp.src.Close()
	}
}

// copier filters one pipe from the command into the stream it stands for.
type copier struct {
	src   *os.File
	dst   *os.File
	f     *filter
	toErr bool // carries the command's stderr, alone or with its stdout

	// mu guards the names f has hidden and the fields below, which Run reads even
	// while the copier is stuck writing. stop sets stopped and the pipe's read
	// deadline together, so a deadline for a quiet moment cannot undo it.
	mu      sync.Mutex
	wrote   bool
	last    byte
	err     error
	stopped bool
}

func (c *copier) run() {
	// A failing destination ends the copying, and closing the pipe then makes the
	// command's next write fail. SIGPIPE then ends even a command that would go on
	// past a failed write, unless it ignores, catches or blocks SIGPIPE, as Python
	// and Ruby do: then it gets EPIPE instead and may run on.
	defer c.src.Close()
	buf := make([]byte, 32<<10)
	if c.pass(buf) {
		c.drain(buf)
	}
}

// pass filters the pipe into the stream until the output ends, writing to the
// stream fails, or stop is called, and reports whether stop was.
func (c *copier) pass(buf []byte) bool {
	for !c.arm() {
		n, err := c.src.Read(buf)
		if n > 0 && !c.put(c.write(buf[:n])) {
			return false
		}
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded):
			// A quiet moment, unless stop ended the read: the rest of a secret may be
			// in the pipe.
			if !c.stopping() && !c.put(c.flush(false)) {
				return false
			}
		default:
			// The end of the output.
			c.put(c.flush(true))
			return false
		}
	}
	return true
}

// drain passes on what the pipe holds, but not what is written to it after.
func (c *copier) drain(buf []byte) {
	for left := unread(c.src); left > 0; {
		n, err := c.src.Read(buf)
		if n > 0 && !c.put(c.write(buf[:n])) {
			return
		}
		if err != nil {
			break
		}
		left -= n
	}
	c.put(c.flush(true))
}

// stop has the copier pass on what the pipe holds and end, rather than wait for
// more from anything the command left running.
func (c *copier) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true
	// Ends a read that is waiting for more.
	_ = c.src.SetReadDeadline(time.Now())
}

// arm sets how long the next read may wait, and reports whether stop has been
// called, after which the pipe is read only for what it holds.
func (c *copier) arm() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var deadline time.Time
	if c.f.holding() && !c.stopped {
		deadline = time.Now().Add(quiet)
	}
	_ = c.src.SetReadDeadline(deadline)
	return c.stopped
}

func (c *copier) stopping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

// unread returns how many bytes the pipe f holds.
func unread(f *os.File) int {
	n := 0
	// Not f.Fd, which would stop the read deadlines working.
	if rc, err := f.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { n, _ = unix.IoctlGetInt(int(fd), fionread) })
	}
	return n
}

// fionread is FIONREAD, _IOR('f', 127, int) in <sys/filio.h>, which x/sys/unix
// does not define for macOS.
const fionread = 0x4004667f

// write and flush call the filter with mu held.
func (c *copier) write(in []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.f.write(in)
}

func (c *copier) flush(end bool) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.f.flush(end)
}

// put passes out on, and reports whether the destination takes more.
func (c *copier) put(out []byte) bool {
	if len(out) == 0 {
		return true
	}
	_, err := c.dst.Write(out)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		c.wrote, c.last = true, out[len(out)-1]
	case !errors.Is(err, syscall.EPIPE):
		c.err = err
	}
	return err == nil
}
