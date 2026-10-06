package launchd_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/launchd"
)

type harness struct {
	m                 launchd.Manager
	loaded            bool
	unsigned          bool
	failNextBootstrap bool
	calls             []string
}

func setup(t *testing.T) *harness {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home & space")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "keyward")
	if err := os.WriteFile(source, []byte("build-one"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{}
	h.m = launchd.Manager{Home: home, Executable: source, UID: 501}
	h.m.Ready = func(string) error {
		if h.loaded {
			return nil
		}
		return errors.New("not running")
	}
	h.m.Command = func(program string, args ...string) error {
		h.calls = append(h.calls, filepath.Base(program)+" "+strings.Join(args, " "))
		if filepath.Base(program) == "codesign" {
			if h.unsigned {
				return errors.New("not Apple-signed")
			}
			return nil
		}
		switch args[0] {
		case "print":
			job := h.m.Label
			if job == "" {
				job = "com.nwokolo24.keyward"
			}
			if !h.loaded || !strings.HasSuffix(args[1], "/"+job) {
				return errors.New("not loaded")
			}
		case "bootout":
			h.loaded = false
		case "bootstrap":
			if h.failNextBootstrap {
				h.failNextBootstrap = false
				return errors.New("bootstrap failed")
			}
			h.loaded = true
		default:
			t.Fatalf("unexpected command: %s %v", program, args)
		}
		return nil
	}
	return h
}

func (h *harness) binary() string { return filepath.Join(h.m.Home, ".local", "bin", "keyward") }
func (h *harness) plist() string {
	return filepath.Join(h.m.Home, "Library", "LaunchAgents", "com.nwokolo24.keyward.plist")
}

func TestInstallSignedCLIWithoutACompanion(t *testing.T) {
	home := t.TempDir()
	executable := filepath.Join(t.TempDir(), "keyward")
	if err := os.WriteFile(executable, []byte("signed-cli-fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	loaded := false
	var calls []string
	m := launchd.Manager{Home: home, Executable: executable, UID: os.Getuid()}
	m.Ready = func(string) error {
		if loaded {
			return nil
		}
		return errors.New("not running")
	}
	m.Command = func(program string, args ...string) error {
		calls = append(calls, filepath.Base(program)+" "+strings.Join(args, " "))
		if filepath.Base(program) == "codesign" {
			if args[len(args)-1] != executable {
				return errors.New("only the signed CLI exists")
			}
			return nil
		}
		if program != "/bin/launchctl" {
			t.Fatalf("unexpected companion command: %s", program)
		}
		switch args[0] {
		case "print":
			if !loaded || !strings.HasSuffix(args[1], "/com.nwokolo24.keyward") {
				return errors.New("not loaded")
			}
		case "bootstrap":
			loaded = true
		default:
			t.Fatalf("unexpected launchctl operation: %v", args)
		}
		return nil
	}
	message, err := m.Run("install")
	if err != nil {
		t.Fatalf("signed CLI-only install: %v", err)
	}
	if !loaded || !strings.Contains(message, filepath.Join(home, ".local", "bin", "keyward")) {
		t.Fatal("CLI-only installation did not start the installed daemon")
	}
	if strings.Count(strings.Join(calls, "\n"), "codesign ") != 1 {
		t.Fatal("installation verified more than the signed CLI")
	}
	plist, err := os.ReadFile(filepath.Join(home, "Library", "LaunchAgents", "com.nwokolo24.keyward.plist"))
	if err != nil || strings.Contains(string(plist), "AssociatedBundleIdentifiers") || strings.Contains(string(plist), "com.nwokolo24.keyward.app") {
		t.Fatalf("CLI-only daemon retained app association: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "Applications")); !os.IsNotExist(err) {
		t.Fatal("CLI-only installation created an application directory")
	}
}

func TestInstallStartsSignedDaemonAndPreservesArguments(t *testing.T) {
	h := setup(t)
	h.m.Socket = filepath.Join(h.m.Home, "private", "daemon.sock")
	h.m.Service = "keyward-dummy-test"
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if !h.loaded {
		t.Fatal("daemon was not registered")
	}
	b, err := os.ReadFile(h.binary())
	if err != nil || string(b) != "build-one" {
		t.Fatalf("installed binary differs: %v", err)
	}
	info, err := os.Stat(h.binary())
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode: %v", err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", h.plist()).CombinedOutput(); err != nil {
		t.Fatalf("invalid launchd plist: %v: %s", err, out)
	}
	out, err := exec.Command("/usr/bin/plutil", "-extract", "ProgramArguments", "json", "-o", "-", h.plist()).Output()
	if err != nil || !strings.Contains(string(out), "home & space") || !strings.Contains(string(out), "daemon") {
		t.Fatalf("launch arguments lost their paths: %v: %s", err, out)
	}
	plist, _ := os.ReadFile(h.plist())
	if !strings.Contains(string(plist), "KEYWARD_SOCKET") || !strings.Contains(string(plist), "keyward-dummy-test") {
		t.Fatal("test service and socket were not retained")
	}
	if strings.Contains(string(plist), "AssociatedBundleIdentifiers") {
		t.Fatal("CLI-only daemon retained app association")
	}
	if strings.Contains(string(plist), "daemon.log") || !strings.Contains(string(plist), "/dev/null") {
		t.Fatal("launchd still writes an unbounded daemon log")
	}
	for _, path := range []string{h.plist(), filepath.Join(h.m.Home, "Library", "Logs", "keyward", "activity.jsonl")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private file %s: %v", path, err)
		}
	}
}

func TestInstallRefusesUnsignedBinaryBeforeChangingAnything(t *testing.T) {
	h := setup(t)
	h.unsigned = true
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("unsigned install succeeded")
	}
	if _, err := os.Stat(h.binary()); !os.IsNotExist(err) {
		t.Fatal("unsigned binary was installed")
	}
	if h.loaded {
		t.Fatal("unsigned daemon started")
	}
}

func TestInstallUpdatesAndRestartsExistingDaemon(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.m.Executable, []byte("build-two"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(h.binary())
	if string(b) != "build-two" || !h.loaded {
		t.Fatal("update did not install and start the new build")
	}
	commands := strings.Join(h.calls, "\n")
	if strings.Index(commands, "bootout") < 0 || strings.Index(commands, "bootout") > strings.Index(commands, "bootstrap") {
		t.Fatal("update started before stopping the prior daemon")
	}
}

func TestFailedUpdateRestoresPreviousInstallation(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	oldPlist, _ := os.ReadFile(h.plist())
	if err := os.WriteFile(h.m.Executable, []byte("build-two"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.m.Service = "changed-service"
	h.failNextBootstrap = true
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("failed bootstrap reported success")
	}
	b, _ := os.ReadFile(h.binary())
	p, _ := os.ReadFile(h.plist())
	if string(b) != "build-one" || string(p) != string(oldPlist) || !h.loaded {
		t.Fatal("previous binary, configuration, and registration were not restored")
	}
}

func TestFailedFirstInstallLeavesNoLoginAgent(t *testing.T) {
	h := setup(t)
	h.failNextBootstrap = true
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("failed install reported success")
	}
	for _, path := range []string{h.binary(), h.plist()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed install left %s", path)
		}
	}
	if h.loaded {
		t.Fatal("failed install left a registered job")
	}
}

func TestReadinessFailureRestoresThePreviousCLIAndPlist(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	oldPlist, err := os.ReadFile(h.plist())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.m.Executable, []byte("build-two"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.m.Service = "changed-service"
	h.m.StartupTimeout = 20 * time.Millisecond
	h.m.Ready = func(string) error {
		binary, err := os.ReadFile(h.binary())
		if err == nil && string(binary) == "build-one" && h.loaded {
			return nil
		}
		return errors.New("new daemon is not responding")
	}
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("unresponsive upgrade reported success")
	}
	binary, err := os.ReadFile(h.binary())
	if err != nil || string(binary) != "build-one" || !h.loaded {
		t.Fatal("readiness failure did not restore the previous daemon")
	}
	plist, err := os.ReadFile(h.plist())
	if err != nil || string(plist) != string(oldPlist) {
		t.Fatal("readiness failure did not restore the previous configuration")
	}
	for path, mode := range map[string]os.FileMode{h.binary(): 0o755, h.plist(): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("rollback changed mode for %s: %v", path, err)
		}
	}
}

func TestInstallWaitsForStartup(t *testing.T) {
	h := setup(t)
	attempts := 0
	h.m.Ready = func(string) error {
		attempts++
		if attempts < 3 {
			return errors.New("not ready yet")
		}
		return nil
	}
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("readiness attempts = %d, want 3", attempts)
	}
}

func TestUninstallStopsAutomaticStartupAndKeepsCLI(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Run("uninstall"); err != nil {
		t.Fatal(err)
	}
	if h.loaded {
		t.Fatal("daemon remains registered")
	}
	if _, err := os.Stat(h.plist()); !os.IsNotExist(err) {
		t.Fatal("startup configuration remains")
	}
	if _, err := os.Stat(h.binary()); err != nil {
		t.Fatal("uninstall removed the CLI")
	}
	if _, err := h.m.Run("uninstall"); err != nil {
		t.Fatalf("repeated uninstall: %v", err)
	}
}

func TestStatusAndInvalidActionDoNotWriteFiles(t *testing.T) {
	h := setup(t)
	status, err := h.m.Run("status")
	if err != nil || !strings.Contains(status, "not running") {
		t.Fatalf("status = %q, %v", status, err)
	}
	if _, err := h.m.Run("unknown"); err == nil {
		t.Fatal("unknown action succeeded")
	}
	if _, err := os.Stat(h.plist()); !os.IsNotExist(err) {
		t.Fatal("read-only action wrote configuration")
	}
}

func TestStatusDoesNotMistakeLoadedJobForRunningDaemon(t *testing.T) {
	h := setup(t)
	h.loaded = true
	h.m.Ready = func(string) error { return errors.New("connection refused") }
	if _, err := h.m.Run("status"); err == nil {
		t.Fatal("loaded but unreachable daemon reported healthy")
	}
}

func TestInstallRefusesInvalidLabel(t *testing.T) {
	h := setup(t)
	h.m.Label = "../another-agent"
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("invalid label was accepted")
	}
	if len(h.calls) != 0 {
		t.Fatal("invalid label reached launchctl")
	}
}
