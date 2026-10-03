//go:build darwin && cgo && integration

package vault_test

import (
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

// Compile and sign this test binary with the daemon's identity and identifier.
// KEYWARD_TEST_DAEMON_BINARY selects an existing signed build, never its live job.
func TestSignedDirectAccessToDaemonItems(t *testing.T) {
	binary := os.Getenv("KEYWARD_TEST_DAEMON_BINARY")
	if binary == "" {
		t.Skip("set KEYWARD_TEST_DAEMON_BINARY and run a signed test binary")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, got := signingMetadata(t, binary), signingMetadata(t, self)
	if want["TeamIdentifier"] == "" || want["TeamIdentifier"] == "not set" ||
		want["TeamIdentifier"] != got["TeamIdentifier"] ||
		want["Identifier"] != got["Identifier"] || want["requirement"] == "" ||
		want["requirement"] != got["requirement"] {
		t.Fatal("test binary must have the daemon's Apple signing team, identifier, and designated requirement")
	}
	if want["CDHash"] == "" || got["CDHash"] == "" || want["CDHash"] == got["CDHash"] {
		t.Fatal("daemon and direct caller must be distinct signed builds")
	}
	t.Log("signing requirements match; code hashes differ")

	dir, err := os.MkdirTemp("/tmp", "kwdirect-")
	if err != nil {
		t.Fatal(err)
	}
	service := "keyward-direct-test-" + filepath.Base(dir)
	log, err := os.OpenFile(filepath.Join(dir, "daemon.log"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "d.sock")
	cmd := exec.Command(binary, "daemon")
	home, _ := os.UserHomeDir()
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "KEYWARD_SERVICE=" + service, "KEYWARD_SOCKET=" + socket, "KEYWARD_LOG_DIR=" + filepath.Join(dir, "logs")}
	cmd.Stdout, cmd.Stderr = log, log
	const first, second = "direct-probe", "delete-probe"
	var done chan error
	stop := func() error {
		if done == nil {
			return nil
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		var err error
		select {
		case err = <-done:
		case <-time.After(4 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			err = errors.New("disposable daemon did not shut down in time")
		}
		done = nil
		return err
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("cleanup daemon: %v", err)
		}
		for _, name := range []string{first, second} {
			_ = exec.Command("/usr/bin/security", "delete-generic-password", "-s", service, "-a", name).Run()
		}
		log.Close()
		os.RemoveAll(dir)
	})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done = make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	client := &daemon.Client{Path: socket, Timeout: 2 * time.Second}
	for deadline := time.Now().Add(4 * time.Second); client.Ping() != nil; {
		if time.Now().After(deadline) {
			t.Fatal("disposable daemon did not become ready")
		}
		time.Sleep(30 * time.Millisecond)
	}
	original := vault.NewSecret([]byte("not-a-real-secret-direct-original"))
	defer original.Destroy()
	for _, name := range []string{first, second} {
		if err := client.Put(name, original, ""); err != nil {
			t.Fatalf("daemon create dummy: %v", err)
		}
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disposable daemon socket still exists")
	}
	t.Log("creator daemon exited and its socket is gone before direct access")

	store := vault.NewKeychainService(service)
	readDirectDummy(t, store, first, original)
	replacement := vault.NewSecret([]byte("not-a-real-secret-direct-replacement"))
	defer replacement.Destroy()
	start := time.Now()
	if err := store.Replace(first, replacement, ""); err != nil {
		t.Fatalf("direct replace: %v", err)
	}
	promptFree(t, "direct replace", start)
	readDirectDummy(t, store, first, replacement)
	for _, name := range []string{first, second} {
		start := time.Now()
		if err := store.Delete(name); err != nil {
			t.Fatalf("direct delete: %v", err)
		}
		promptFree(t, "direct delete "+name, start)
		if _, err := store.Get(name); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("deleted dummy was still readable")
		}
	}
	entries, err := store.Entries()
	if err != nil || len(entries) != 0 {
		t.Fatal("disposable service still contains entries after deletion")
	}
}

func signingMetadata(t *testing.T, binary string) map[string]string {
	t.Helper()
	out, err := exec.Command("/usr/bin/codesign", "-d", "--verbose=4", "-r-", binary).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect signing metadata: %v", err)
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if requirement, ok := strings.CutPrefix(line, "designated => "); ok {
			fields["requirement"] = requirement
		} else if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = value
		}
	}
	return fields
}

func readDirectDummy(t *testing.T, store vault.Store, name string, want vault.Secret) {
	t.Helper()
	start := time.Now()
	got, err := store.Get(name)
	if err != nil {
		t.Fatalf("direct read: %v", err)
	}
	defer got.Destroy()
	if sha256.Sum256(got.Bytes()) != sha256.Sum256(want.Bytes()) {
		t.Fatal("direct read value does not match the dummy digest")
	}
	promptFree(t, "direct read", start)
}

func promptFree(t *testing.T, operation string, start time.Time) {
	t.Helper()
	elapsed := time.Since(start)
	t.Logf("%s: %s", operation, elapsed.Round(time.Microsecond))
	if elapsed >= 2*time.Second {
		t.Fatalf("%s took at least two seconds; prompt-free result is inconclusive", operation)
	}
}
