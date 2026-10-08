package daemon_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

// untouched fails the test if a request reaches it.
type untouched struct {
	vault.Store
	t *testing.T
}

func (u untouched) Get(name string) (vault.Secret, error) {
	u.t.Errorf("the outdated daemon received get %q", name)
	return vault.Secret{}, vault.ErrNotFound
}

func seeded(t *testing.T) vault.Store {
	t.Helper()
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"api-token": "fixture-value"}); err != nil {
		t.Fatal(err)
	}
	return store
}

// serveOn runs srv on path and returns a function that stops it.
func serveOn(t *testing.T, path string, srv *daemon.Server) func() {
	t.Helper()
	l, err := daemon.Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			l.Close()
			<-done
		}
	}
	t.Cleanup(stop)
	return stop
}

// After brew upgrade, the old daemon keeps running; it must be replaced before use.
func TestOutdatedDaemonIsRestartedBeforeTheFirstRequest(t *testing.T) {
	path := socketPath(t)
	stopOld := serveOn(t, path, &daemon.Server{Store: untouched{vault.NewMemory(), t}, Version: "0.1.8"})
	restarts := 0
	c := &daemon.Client{Path: path, Version: "0.1.9", Restart: func() error {
		restarts++
		stopOld()
		serveOn(t, path, &daemon.Server{Store: seeded(t), Version: "0.1.9"})
		return nil
	}}
	if _, err := c.Get("api-token"); err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if _, err := c.Get("api-token"); err != nil || restarts != 1 {
		t.Fatalf("second Get: %v, restarts %d", err, restarts)
	}
}

// Daemons before the version check do not report one.
func TestUnversionedDaemonCountsAsOutdated(t *testing.T) {
	path := socketPath(t)
	serveOn(t, path, &daemon.Server{Store: untouched{vault.NewMemory(), t}})
	c := &daemon.Client{Path: path, Version: "0.1.9"}
	_, err := c.Get("api-token")
	if !errors.Is(err, daemon.ErrOutdated) || !strings.Contains(err.Error(), "keyward service install") {
		t.Fatalf("Get = %v, want ErrOutdated with the fix", err)
	}
}

func TestMatchingAndDevelopmentVersionsAreNotRestarted(t *testing.T) {
	for _, versions := range [][2]string{{"0.1.9", "0.1.9"}, {"0.1.8", "dev"}, {"0.1.8", ""}} {
		path := socketPath(t)
		serveOn(t, path, &daemon.Server{Store: seeded(t), Version: versions[0]})
		c := &daemon.Client{Path: path, Version: versions[1], Restart: func() error {
			t.Errorf("daemon %s restarted for client %q", versions[0], versions[1])
			return nil
		}}
		if _, err := c.Get("api-token"); err != nil {
			t.Fatalf("%v: %v", versions, err)
		}
	}
}

func TestFailedRestartSendsNothing(t *testing.T) {
	path := socketPath(t)
	serveOn(t, path, &daemon.Server{Store: untouched{vault.NewMemory(), t}, Version: "0.1.8"})
	c := &daemon.Client{Path: path, Version: "0.1.9", Restart: func() error { return errors.New("brew failed") }}
	if _, err := c.Get("api-token"); err == nil || !strings.Contains(err.Error(), "brew failed") {
		t.Fatalf("Get = %v, want the restart failure", err)
	}
}

func TestRestartThatLeavesTheOldDaemonIsReported(t *testing.T) {
	path := socketPath(t)
	serveOn(t, path, &daemon.Server{Store: untouched{vault.NewMemory(), t}, Version: "0.1.8"})
	c := &daemon.Client{Path: path, Version: "0.1.9", Restart: func() error { return nil }}
	if _, err := c.Get("api-token"); !errors.Is(err, daemon.ErrOutdated) {
		t.Fatalf("Get = %v, want ErrOutdated", err)
	}
}
