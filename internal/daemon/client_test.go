package daemon_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

func servePath(t *testing.T, path string, store vault.Store) error {
	t.Helper()
	l, err := daemon.Listen(path)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- (&daemon.Server{Store: store}).Serve(l) }()
	t.Cleanup(func() {
		l.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return nil
}

func TestClientStartsBeforeVaultRequests(t *testing.T) {
	for _, op := range []string{"get", "put", "replace", "delete", "entries"} {
		t.Run(op, func(t *testing.T) {
			store := vault.NewMemory()
			if op != "put" {
				if err := store.Seed(map[string]string{"dummy": "fixture-original"}); err != nil {
					t.Fatal(err)
				}
			}
			starts := 0
			c := &daemon.Client{Path: socketPath(t)}
			c.Start = func() error {
				starts++
				return servePath(t, c.Path, store)
			}
			value := vault.NewSecret([]byte("fixture-replacement"))
			defer value.Destroy()
			switch op {
			case "get":
				got, err := c.Get("dummy")
				if err != nil {
					t.Fatal(err)
				}
				defer got.Destroy()
				if sha256.Sum256(got.Bytes()) != sha256.Sum256([]byte("fixture-original")) {
					t.Fatal("Get did not resolve the fixture")
				}
			case "put", "replace":
				var err error
				if op == "put" {
					err = c.Put("dummy", value, "")
				} else {
					err = c.Replace("dummy", value, "")
				}
				if err != nil {
					t.Fatal(err)
				}
				got, err := store.Get("dummy")
				if err != nil {
					t.Fatal(err)
				}
				defer got.Destroy()
				if sha256.Sum256(got.Bytes()) != sha256.Sum256(value.Bytes()) {
					t.Fatal("write did not reach the store")
				}
			case "delete":
				if err := c.Delete("dummy"); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Get("dummy"); !errors.Is(err, vault.ErrNotFound) {
					t.Fatal("Delete did not reach the store")
				}
			case "entries":
				entries, err := c.Entries()
				if err != nil || len(entries) != 1 || entries[0].Name != "dummy" {
					t.Fatalf("Entries = %v, %v", entries, err)
				}
			}
			if _, err := c.Entries(); err != nil {
				t.Fatal(err)
			}
			if starts != 1 {
				t.Errorf("Start called %d times, want one startup and healthy reuse", starts)
			}
		})
	}
}

func TestClientStartsForRefusedSocket(t *testing.T) {
	path := socketPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	starts := 0
	c := &daemon.Client{Path: path}
	c.Start = func() error {
		starts++
		return servePath(t, path, vault.NewMemory())
	}
	if _, err := c.Entries(); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Errorf("Start called %d times, want one", starts)
	}
}

func TestClientStartupFailurePropagates(t *testing.T) {
	want := errors.New("fixture startup failed")
	starts := 0
	c := &daemon.Client{Path: socketPath(t), Start: func() error { starts++; return want }}
	err := c.Delete("dummy")
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "keyward service install") {
		t.Fatalf("Delete = %v, want startup cause and recovery guidance", err)
	}
	if starts != 1 {
		t.Errorf("Start called %d times, want one", starts)
	}
}

func TestClientRetriesOnlyOnceAfterStartup(t *testing.T) {
	starts := 0
	c := &daemon.Client{Path: socketPath(t), Start: func() error { starts++; return nil }}
	_, err := c.Entries()
	if !errors.Is(err, daemon.ErrNotRunning) {
		t.Fatalf("Entries = %v, want ErrNotRunning after unsuccessful startup", err)
	}
	if !strings.Contains(err.Error(), "keyward service install") || strings.Contains(err.Error(), "`keyward daemon`") {
		t.Errorf("installed service recovery = %q, want service-only guidance", err)
	}
	if starts != 1 {
		t.Errorf("Start called %d times, want one", starts)
	}
}

func TestClientPingNeverStarts(t *testing.T) {
	starts := 0
	c := &daemon.Client{Path: socketPath(t), Start: func() error { starts++; return nil }}
	if err := c.Ping(); !errors.Is(err, daemon.ErrNotRunning) {
		t.Fatalf("Ping = %v, want ErrNotRunning", err)
	}
	if starts != 0 {
		t.Errorf("Start called %d times during Ping", starts)
	}
}

func TestClientDoesNotStartForOtherDialErrors(t *testing.T) {
	starts := 0
	c := &daemon.Client{Path: strings.Repeat("x", 256), Start: func() error { starts++; return nil }}
	if _, err := c.Entries(); err == nil || errors.Is(err, daemon.ErrNotRunning) {
		t.Fatalf("Entries = %v, want an ordinary connection error", err)
	}
	if starts != 0 {
		t.Errorf("Start called %d times for another dial error", starts)
	}
}

func TestClientDoesNotStartForPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass directory permissions")
	}
	c := start(t, &daemon.Server{Store: vault.NewMemory()})
	dir := filepath.Dir(c.Path)
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	starts := 0
	c.Start = func() error { starts++; return nil }
	if _, err := c.Entries(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Entries = %v, want a permission error", err)
	}
	if starts != 0 {
		t.Errorf("Start called %d times for a permission error", starts)
	}
}

func TestClientDoesNotReplayWriteAfterDisconnect(t *testing.T) {
	path := socketPath(t)
	l, err := daemon.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	store := vault.NewMemory()
	done := make(chan error, 1)
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if errors.Is(err, net.ErrClosed) {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
			accepted.Add(1)
			var req struct {
				Op, Name string
				Value    []byte
			}
			err = json.NewDecoder(conn).Decode(&req)
			if err == nil && req.Op != "put" {
				err = errors.New("fixture expected a put request")
			}
			if err == nil {
				value := vault.NewSecret(req.Value)
				clear(req.Value)
				err = store.Put(req.Name, value, "")
				value.Destroy()
			}
			conn.Close()
			if err != nil && !errors.Is(err, vault.ErrExists) {
				done <- err
				return
			}
		}
	}()
	starts := 0
	c := &daemon.Client{Path: path, Timeout: 100 * time.Millisecond, Start: func() error { starts++; return nil }}
	value := vault.NewSecret([]byte("fixture-write"))
	defer value.Destroy()
	if err := c.Put("dummy", value, ""); err == nil {
		t.Fatal("Put succeeded without a response")
	}
	l.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("dummy")
	if err != nil {
		t.Fatal("write did not take effect before the disconnect")
	}
	defer got.Destroy()
	if sha256.Sum256(got.Bytes()) != sha256.Sum256(value.Bytes()) {
		t.Fatal("stored fixture digest differs")
	}
	if starts != 0 || accepted.Load() != 1 {
		t.Errorf("starts = %d, connections = %d after a sent write", starts, accepted.Load())
	}
}
