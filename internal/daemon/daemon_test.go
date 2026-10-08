package daemon_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/vault"
	"github.com/veilux-lab/keyward/internal/vault/vaulttest"
)

// socketPath returns a path in a fresh directory. Not t.TempDir: macOS caps a
// socket path at 104 bytes, and test temp directories can exceed it.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kwd")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "sub", "d.sock")
}

// start serves store on a fresh socket and returns a client for it.
func start(t *testing.T, srv *daemon.Server) *daemon.Client {
	t.Helper()
	path := socketPath(t)
	l, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() {
		l.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &daemon.Client{Path: path}
}

// The client is held to the same contract as the stores it fronts. That is what
// lets every command switch to it without changing.
func TestClientContract(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store {
		return start(t, &daemon.Server{Store: vault.NewMemory()})
	})
}

// Callers branch on these with errors.Is, so each has to survive the socket.
func TestErrorsRoundTrip(t *testing.T) {
	for _, sentinel := range []error{
		vault.ErrNotFound, vault.ErrExists, vault.ErrEmptyValue, vault.ErrDenied,
		handle.ErrInvalidName, handle.ErrEmptyName, handle.ErrNameTooLong,
	} {
		c := start(t, &daemon.Server{Store: failingStore{err: sentinel}})
		if _, err := c.Get("anything"); !errors.Is(err, sentinel) {
			t.Errorf("Get = %v, want errors.Is %v", err, sentinel)
		}
	}
}

// Any other failure arrives with its message, which says what went wrong.
func TestOtherErrorsKeepTheirMessage(t *testing.T) {
	c := start(t, &daemon.Server{Store: failingStore{err: errors.New("keychain is locked")}})
	_, err := c.Entries()
	if err == nil || !strings.Contains(err.Error(), "keychain is locked") {
		t.Errorf("Entries = %v, want the server's message", err)
	}
}

func TestPingDoesNotReachTheStore(t *testing.T) {
	c := start(t, &daemon.Server{Store: failingStore{err: errors.New("store must not be called")}})
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping = %v", err)
	}
}

func TestNotRunning(t *testing.T) {
	c := &daemon.Client{Path: socketPath(t)}
	_, err := c.Get("anything")
	if !errors.Is(err, daemon.ErrNotRunning) {
		t.Fatalf("Get = %v, want ErrNotRunning", err)
	}
	if !strings.Contains(err.Error(), "keyward service install") {
		t.Errorf("error = %q, want service installation guidance", err)
	}
	if !strings.Contains(err.Error(), "for development or isolated use, run `keyward daemon`") {
		t.Errorf("error = %q, want isolated development startup guidance", err)
	}
}

// A request waiting on a Keychain prompt must not hang the command forever, and
// the error has to point at the prompt, which is the likely cause.
func TestClientTimesOut(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	c := start(t, &daemon.Server{Store: blockingStore{release: release}})
	c.Timeout = 100 * time.Millisecond
	starts := 0
	c.Start = func() error { starts++; return nil }

	_, err := c.Get("anything")
	if err == nil || !strings.Contains(err.Error(), "Keychain prompt") {
		t.Errorf("Get = %v, want a timeout pointing at the Keychain prompt", err)
	}
	if starts != 0 {
		t.Errorf("Start called %d times after a sent request", starts)
	}
}

// ===========================================================================
// Access
// ===========================================================================

// A refused connection must never reach the store.
func TestUnauthorizedConnectionsAreRefused(t *testing.T) {
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"token": "value"}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	c := start(t, &daemon.Server{
		Store:     store,
		Authorize: func(net.Conn) error { return errors.New("uid 501 is not uid 502") },
	})

	_, err := c.Get("token")
	if !errors.Is(err, vault.ErrDenied) {
		t.Errorf("Get = %v, want ErrDenied", err)
	}
}

// The default check reads the peer's uid from the socket. The same user must pass.
func TestSameUserIsAuthorized(t *testing.T) {
	c := start(t, &daemon.Server{Store: vault.NewMemory()})
	if _, err := c.Entries(); err != nil {
		t.Errorf("Entries as the same user = %v, want success", err)
	}
}

func TestSocketIsPrivate(t *testing.T) {
	path := socketPath(t)
	l, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	for p, want := range map[string]os.FileMode{filepath.Dir(path): 0o700, path: 0o600} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", filepath.Base(p), got, want)
		}
	}
}

// ===========================================================================
// Lifecycle
// ===========================================================================

func TestOnlyOneDaemonAtATime(t *testing.T) {
	path := socketPath(t)
	first, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer first.Close()

	if second, err := daemon.Listen(path); err == nil {
		second.Close()
		t.Fatal("a second daemon started on the same socket")
	} else if !errors.Is(err, daemon.ErrRunning) {
		t.Errorf("error = %v, want daemon.ErrRunning", err)
	}
}

// A daemon that crashed leaves its socket behind. The next one must not be
// blocked by it.
func TestStaleSocketIsReplaced(t *testing.T) {
	path := socketPath(t)
	first, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	first.Close()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("leaving a stale socket: %v", err)
	}

	second, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	second.Close()
}

func TestCloseRemovesTheSocket(t *testing.T) {
	path := socketPath(t)
	l, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	l.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("socket still present after Close: %v", err)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	path := socketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, path, vault.NewMemory(), nil) }()

	c := &daemon.Client{Path: path}
	waitFor(t, func() bool { _, err := c.Entries(); return err == nil })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := c.Entries(); !errors.Is(err, daemon.ErrNotRunning) {
		t.Errorf("Entries after shutdown = %v, want ErrNotRunning", err)
	}
}

func TestRunStopsWithBlockedRequest(t *testing.T) {
	path := socketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, path, shutdownStore{entered: entered, release: release}, nil) }()
	waitFor(t, func() bool { _, err := os.Stat(path); return err == nil })

	clientDone := make(chan error, 1)
	go func() {
		_, err := (&daemon.Client{Path: path}).Get("dummy")
		clientDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach the store")
	}
	cancel()
	waitFor(t, func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
	if next, err := daemon.Listen(path); err == nil {
		next.Close()
		t.Fatal("another daemon started while the old request was draining")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung on a blocked store request")
	}
	select {
	case err := <-clientDone:
		if err == nil {
			t.Error("interrupted request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not disconnect the waiting client")
	}
	next, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("instance lock was not released after shutdown: %v", err)
	}
	next.Close()
}

func TestShutdownFinishesRequestsWithinGracePeriod(t *testing.T) {
	path := socketPath(t)
	l, err := daemon.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	srv := &daemon.Server{Store: shutdownStore{entered: entered, release: release}}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	clientDone := make(chan error, 1)
	go func() {
		_, err := (&daemon.Client{Path: path}).Get("dummy")
		clientDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach the store")
	}
	l.Close()
	select {
	case <-done:
		t.Fatal("shutdown did not wait for the in-flight request")
	case <-time.After(20 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-clientDone; !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("in-flight request = %v, want ErrNotFound", err)
	}
	if err := <-done; err != nil {
		t.Errorf("Serve = %v", err)
	}
}

// ===========================================================================
// What the daemon writes down
// ===========================================================================

// The log is for seeing who asked for what. Names, never values.
func TestLogNamesButNeverValues(t *testing.T) {
	const value = "ghp_neverInTheLog0123456789"
	var log syncBuffer
	c := start(t, &daemon.Server{Store: vault.NewMemory(), Log: &log})

	if err := c.Put("github-token", vault.NewSecret([]byte(value)), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := c.Get("github-token"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	out := log.String()
	if !strings.Contains(out, "github-token") {
		t.Errorf("log does not name the secret:\n%s", out)
	}
	if strings.Contains(out, value) {
		t.Errorf("log contains the value:\n%s", out)
	}
}

// ===========================================================================
// Malformed requests
// ===========================================================================

func TestUnknownOperationIsRejected(t *testing.T) {
	c := start(t, &daemon.Server{Store: vault.NewMemory()})
	resp := rawRequest(t, c.Path, []byte(`{"op":"dump-everything"}`+"\n"))
	if !strings.Contains(resp, "unknown operation") {
		t.Errorf("response = %s, want the operation refused", resp)
	}
}

func TestOversizedRequestIsRejected(t *testing.T) {
	c := start(t, &daemon.Server{Store: vault.NewMemory()})
	huge := bytes.Repeat([]byte("a"), 2<<20)
	req, _ := json.Marshal(map[string]any{"op": "put", "name": "big", "value": huge})
	resp := rawRequest(t, c.Path, append(req, '\n'))
	if !strings.Contains(resp, "code") {
		t.Errorf("response = %.200s, want an error", resp)
	}
	if _, err := c.Get("big"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get(big) = %v, want the oversized value not stored", err)
	}
}

// ===========================================================================
// Helpers
// ===========================================================================

func rawRequest(t *testing.T, path string, req []byte) string {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(req)
	var buf bytes.Buffer
	buf.ReadFrom(conn)
	return buf.String()
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

type failingStore struct {
	vault.Store
	err error
}

func (f failingStore) Get(string) (vault.Secret, error) { return vault.Secret{}, f.err }
func (f failingStore) Entries() ([]vault.Entry, error)  { return nil, f.err }

type blockingStore struct {
	vault.Store
	release chan struct{}
}

type shutdownStore struct {
	vault.Store
	entered chan struct{}
	release chan struct{}
}

func (s shutdownStore) Get(string) (vault.Secret, error) {
	close(s.entered)
	<-s.release
	return vault.Secret{}, vault.ErrNotFound
}

func (b blockingStore) Get(string) (vault.Secret, error) {
	<-b.release
	return vault.Secret{}, vault.ErrNotFound
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
