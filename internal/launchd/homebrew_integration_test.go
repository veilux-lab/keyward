//go:build darwin && integration

package launchd_test

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

func TestHomebrewBinaryRestartPersistence(t *testing.T) {
	binary := os.Getenv("KEYWARD_TEST_HOMEBREW_BINARY")
	if binary == "" {
		t.Skip("set KEYWARD_TEST_HOMEBREW_BINARY to the formula-installed CLI")
	}
	dir, err := os.MkdirTemp("/tmp", "kwbrew-")
	if err != nil {
		t.Fatal(err)
	}
	service := "keyward-homebrew-test-" + filepath.Base(dir)
	const name = "brew-probe"
	home, _ := os.UserHomeDir()
	socket := filepath.Join(dir, "d.sock")
	client := &daemon.Client{Path: socket, Timeout: 2 * time.Second}
	var cmd *exec.Cmd
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
			err = errors.New("disposable daemon did not stop")
		}
		done = nil
		return err
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		_ = exec.Command("/usr/bin/security", "delete-generic-password", "-s", service+"-vault-key", "-a", "master").Run()
		os.RemoveAll(dir)
	})
	start := func() {
		cmd = exec.Command(binary, "daemon")
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "KEYWARD_SERVICE=" + service, "KEYWARD_SOCKET=" + socket, "KEYWARD_VAULT=" + filepath.Join(dir, "test.vault"), "KEYWARD_LOG_DIR=" + filepath.Join(dir, "logs")}
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done = make(chan error, 1)
		wait := done
		go func() { wait <- cmd.Wait() }()
		for deadline := time.Now().Add(4 * time.Second); client.Ping() != nil; {
			if time.Now().After(deadline) {
				t.Fatal("disposable daemon did not become ready")
			}
			time.Sleep(30 * time.Millisecond)
		}
	}
	start()
	value := vault.NewSecret([]byte("not-a-real-secret-homebrew-fixture"))
	defer value.Destroy()
	if err := client.Put(name, value, ""); err != nil {
		t.Fatalf("create dummy: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	start()
	begin := time.Now()
	got, err := client.Get(name)
	if err != nil {
		t.Fatalf("read after restart: %v", err)
	}
	defer got.Destroy()
	if sha256.Sum256(got.Bytes()) != sha256.Sum256(value.Bytes()) {
		t.Fatal("dummy changed across restart")
	}
	if elapsed := time.Since(begin); elapsed >= 2*time.Second {
		t.Fatalf("read took %s; prompt-free access is inconclusive", elapsed)
	} else {
		t.Logf("formula binary read its dummy after restart in %s", elapsed)
	}
	if err := client.Delete(name); err != nil {
		t.Fatal(err)
	}
}
