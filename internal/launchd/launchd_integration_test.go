//go:build darwin && integration

package launchd_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/launchd"
	"github.com/veilux-lab/keyward/internal/vault"
)

// The two binaries must be distinct builds signed with the same Apple identity.
// A separate job, socket, home directory, and service protect the real setup.
func TestSignedInstallLifecycle(t *testing.T) {
	first, second := os.Getenv("KEYWARD_TEST_BINARY"), os.Getenv("KEYWARD_TEST_UPGRADE_BINARY")
	if first == "" || second == "" {
		t.Skip("set KEYWARD_TEST_BINARY and KEYWARD_TEST_UPGRADE_BINARY to signed builds")
	}
	dir, err := os.MkdirTemp("/tmp", "kwsvc-")
	if err != nil {
		t.Fatal(err)
	}
	label := "com.nwokolo24.keyward.test." + filepath.Base(dir)
	service := "keyward-install-test-" + filepath.Base(dir)
	m := launchd.Manager{Home: dir, UID: os.Getuid(), Executable: first, Label: label, Socket: filepath.Join(dir, "d.sock"), Service: service}
	client := &daemon.Client{Path: m.Socket, Timeout: 2 * time.Second}
	const name = "install-probe"
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-generic-password", "-s", service, "-a", name).Run()
		if _, err := m.Run("uninstall"); err != nil {
			t.Errorf("cleanup login agent: %v", err)
		}
		os.RemoveAll(dir)
	})
	if _, err := m.Run("install"); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if status, err := m.Run("status"); err != nil || !strings.Contains(status, "running") {
		t.Fatalf("status = %q, %v", status, err)
	}
	value := vault.NewSecret([]byte("not-a-real-secret-install-one"))
	defer value.Destroy()
	if err := client.Put(name, value, ""); err != nil {
		t.Fatalf("store dummy: %v", err)
	}
	target := fmt.Sprintf("gui/%d/%s", m.UID, label)
	before := agentPID(t, target)
	m.Executable = second
	if _, err := m.Run("install"); err != nil {
		t.Fatalf("signed upgrade: %v", err)
	}
	if after := agentPID(t, target); after == before || after == 0 {
		t.Fatal("upgrade did not start a new daemon process")
	}
	assertDummy(t, client, name, value)
	replacement := vault.NewSecret([]byte("not-a-real-secret-install-two"))
	defer replacement.Destroy()
	start := time.Now()
	if err := client.Replace(name, replacement, ""); err != nil {
		t.Fatalf("replace across signed builds: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("replace took %s; prompt-free result is inconclusive", elapsed)
	}
	assertDummy(t, client, name, replacement)
	t.Logf("signed rebuild read and replacement succeeded in under two seconds")

	before = agentPID(t, target)
	if err := exec.Command("/bin/launchctl", "kill", "SIGTERM", target).Run(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(8 * time.Second); ; {
		if pid := agentPID(t, target); pid != 0 && pid != before && client.Ping() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("launchd did not restart the daemon")
		}
		time.Sleep(50 * time.Millisecond)
	}
	assertDummy(t, client, name, replacement)
	if err := client.Delete(name); err != nil {
		t.Fatalf("delete dummy: %v", err)
	}
	if _, err := m.Run("uninstall"); err != nil {
		t.Fatal(err)
	}
	if status, err := m.Run("status"); err != nil || !strings.Contains(status, "not loaded") {
		t.Fatalf("uninstalled status = %q, %v", status, err)
	}
	t.Log("launchd restart, persistence, and uninstall succeeded")
}

func agentPID(t *testing.T, target string) int {
	t.Helper()
	out, err := exec.Command("/bin/launchctl", "print", target).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = "); ok {
			pid, _ := strconv.Atoi(value)
			return pid
		}
	}
	return 0
}

func assertDummy(t *testing.T, client *daemon.Client, name string, want vault.Secret) {
	t.Helper()
	start := time.Now()
	got, err := client.Get(name)
	if err != nil {
		t.Fatalf("read dummy: %v", err)
	}
	defer got.Destroy()
	if sha256.Sum256(got.Bytes()) != sha256.Sum256(want.Bytes()) {
		t.Fatal("dummy value changed")
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("read took %s; prompt-free result is inconclusive", elapsed)
	}
}
