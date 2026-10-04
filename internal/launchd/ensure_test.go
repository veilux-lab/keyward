package launchd_test

import (
	"bytes"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/launchd"
)

type brewStartup struct {
	m      launchd.Homebrew
	mu     sync.Mutex
	loaded bool
	ready  bool
	signed bool
	fail   bool
	calls  []string
}

func brewSetup(t *testing.T) *brewStartup {
	t.Helper()
	h := &brewStartup{}
	h.m = launchd.Homebrew{Home: t.TempDir(), UID: os.Getuid(), Brew: "/opt/homebrew/bin/brew", StartupTimeout: 40 * time.Millisecond}
	h.m.Command = func(program string, args ...string) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls = append(h.calls, filepath.Base(program)+" "+strings.Join(args, " "))
		if program == h.m.Brew {
			if h.fail {
				return errors.New("service command failed")
			}
			h.loaded = args[1] != "stop"
			h.ready = h.loaded
			return nil
		}
		if args[0] == "print" && (strings.HasSuffix(args[1], "/com.veilux-lab.keyward.homebrew") && h.loaded || strings.HasSuffix(args[1], "/com.nwokolo24.keyward") && h.signed) {
			return nil
		}
		return errors.New("not loaded")
	}
	h.m.Ready = func(string) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.ready {
			return nil
		}
		return errors.New("not responding")
	}
	return h
}

func startupDir(home string) string { return filepath.Dir(daemon.DefaultSocket(home)) }

func TestHomebrewEnsureStartsOnceWithoutRestarting(t *testing.T) {
	h := brewSetup(t)
	var wg sync.WaitGroup
	for range 8 {
		m := h.m
		wg.Go(func() {
			if err := m.Ensure(); err != nil {
				t.Errorf("ensure: %v", err)
			}
		})
	}
	wg.Wait()
	calls := strings.Join(h.calls, "\n")
	if strings.Count(calls, "brew services start veilux-lab/keyward/keyward") != 1 || strings.Contains(calls, "restart") {
		t.Fatalf("startup commands: %s", calls)
	}
	for path, mode := range map[string]os.FileMode{startupDir(h.m.Home): 0o700, filepath.Join(startupDir(h.m.Home), "startup.lock"): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("private startup path %s: %v", path, err)
		}
	}
}

func TestHomebrewEnsureReusesAnExistingDaemonWithoutWriting(t *testing.T) {
	h := brewSetup(t)
	h.ready, h.signed = true, true
	if err := h.m.Ensure(); err != nil {
		t.Fatal(err)
	}
	if len(h.calls) != 0 {
		t.Fatal("ready daemon caused service commands")
	}
	if _, err := os.Stat(filepath.Join(h.m.Home, "Library")); !os.IsNotExist(err) {
		t.Fatal("ready daemon caused startup state writes")
	}
}

func TestHomebrewEnsureRespectsExplicitStopAndSuccessfulInstall(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Run("uninstall"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("ensure after stop: %v", err)
	}
	if len(h.calls) != 0 {
		t.Fatal("disabled startup reached service manager")
	}
	h.fail = true
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("failed install succeeded")
	}
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("failed install cleared disabled preference")
	}
	h.fail = false
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(startupDir(h.m.Home), "startup.disabled")); !os.IsNotExist(err) {
		t.Fatal("successful install retained disabled preference")
	}
}

func TestHomebrewEnsureDoesNotRestartLoadedOrSignedJobs(t *testing.T) {
	for _, signed := range []bool{false, true} {
		h := brewSetup(t)
		h.loaded, h.signed = !signed, signed
		if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "service install") {
			t.Fatalf("loaded but unhealthy job: %v", err)
		}
		if strings.Contains(strings.Join(h.calls, "\n"), "brew services") {
			t.Fatal("ensure changed an already loaded job")
		}
	}
}

func TestEnsureAndUninstallShareTheStartupLock(t *testing.T) {
	h := brewSetup(t)
	h.m.StartupTimeout = time.Second
	started, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	command := h.m.Command
	h.m.Command = func(program string, args ...string) error {
		if program == h.m.Brew && args[1] == "start" {
			close(started)
			<-release
		}
		if program == h.m.Brew && args[1] == "stop" {
			close(stopped)
		}
		return command(program, args...)
	}
	ensureDone, stopDone := make(chan error, 1), make(chan error, 1)
	go func() { ensureDone <- h.m.Ensure() }()
	<-started
	go func() { _, err := h.m.Run("uninstall"); stopDone <- err }()
	select {
	case <-stopped:
		t.Fatal("uninstall raced startup")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-ensureDone; err != nil {
		t.Fatal(err)
	}
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("lazy startup undid the serialized uninstall")
	}
}

func TestStartupLockIsBounded(t *testing.T) {
	h := brewSetup(t)
	dir := startupDir(h.m.Home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "startup.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "startup lock") {
		t.Fatalf("contended startup: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second || len(h.calls) != 0 {
		t.Fatal("contended startup was unbounded or ran service commands")
	}
}

func TestUnsafeStartupStateCannotStartOrStopServices(t *testing.T) {
	for _, unsafe := range []string{"directory mode", "directory link", "lock mode", "lock link", "disabled link"} {
		t.Run(unsafe, func(t *testing.T) {
			h := brewSetup(t)
			dir := startupDir(h.m.Home)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(t.TempDir(), "victim")
			os.WriteFile(victim, []byte("fixture"), 0o600)
			switch unsafe {
			case "directory mode":
				os.Chmod(dir, 0o755)
			case "directory link":
				os.Remove(dir)
				os.Symlink(t.TempDir(), dir)
			case "lock mode":
				os.WriteFile(filepath.Join(dir, "startup.lock"), nil, 0o644)
			case "lock link":
				os.Symlink(victim, filepath.Join(dir, "startup.lock"))
			case "disabled link":
				os.Symlink(victim, filepath.Join(dir, "startup.disabled"))
			}
			if err := h.m.Ensure(); err == nil {
				t.Fatal("unsafe state started a service")
			}
			if _, err := h.m.Run("uninstall"); err == nil {
				t.Fatal("unsafe state stopped a service")
			}
			if len(h.calls) != 0 {
				t.Fatal("unsafe state reached service commands")
			}
			got, err := os.ReadFile(victim)
			if err != nil || string(got) != "fixture" {
				t.Fatal("unsafe state changed a symlink target")
			}
		})
	}
}

func TestSignedEnsureRequiresAnInstalledDaemon(t *testing.T) {
	h := setup(t)
	h.m.Ready = func(string) error { return errors.New("not running") }
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "make install") {
		t.Fatalf("missing installed daemon: %v", err)
	}
	if _, err := os.Stat(h.binary()); !os.IsNotExist(err) {
		t.Fatal("ensure copied the development binary")
	}
	if strings.Contains(strings.Join(h.calls, "\n"), "codesign") {
		t.Fatal("ensure verified a development build instead of the installed daemon")
	}
}

func TestSignedEnsureBootstrapsTheInstalledBuild(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	h.loaded = false
	h.m.Ready = func(string) error {
		if h.loaded {
			return nil
		}
		return errors.New("not running")
	}
	os.WriteFile(h.m.Executable, []byte("uninstalled-build-two"), 0o755)
	h.calls = nil
	if err := h.m.Ensure(); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(h.calls, "\n")
	if !strings.Contains(calls, "bootstrap gui/501 "+h.plist()) || !strings.Contains(calls, "codesign") || strings.Contains(calls, h.m.Executable) || strings.Contains(calls, "bootout") {
		t.Fatalf("ensure did not reuse installed configuration: %s", calls)
	}
	got, err := os.ReadFile(h.binary())
	if err != nil || string(got) != "build-one" {
		t.Fatal("ensure replaced the installed binary")
	}
}

func TestSignedEnsureReusesALoadedHomebrewDaemon(t *testing.T) {
	m := launchd.Manager{Home: t.TempDir(), UID: os.Getuid(), StartupTimeout: 40 * time.Millisecond}
	readyCalls := 0
	m.Ready = func(string) error {
		readyCalls++
		if readyCalls >= 3 {
			return nil
		}
		return errors.New("not ready yet")
	}
	m.Command = func(program string, args ...string) error {
		if filepath.Base(program) == "launchctl" && args[0] == "print" {
			if strings.HasSuffix(args[1], "/com.veilux-lab.keyward.homebrew") {
				return nil
			}
			return errors.New("not loaded")
		}
		t.Fatalf("ensure changed a loaded Homebrew daemon: %s %v", program, args)
		return nil
	}
	if err := m.Ensure(); err != nil {
		t.Fatal(err)
	}
}

func TestSignedUninstallDisablesHomebrewLazyStartup(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("uninstall"); err != nil {
		t.Fatal(err)
	}
	b := brewSetup(t)
	b.m.Home = h.m.Home
	if err := b.m.Ensure(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("signed uninstall was not respected by Homebrew startup")
	}
	if len(b.calls) != 0 {
		t.Fatal("Homebrew started after signed uninstall")
	}
}

func TestSignedInstallPreservesIsolatedNamespaces(t *testing.T) {
	for _, namespace := range []string{"label", "socket", "service"} {
		t.Run(namespace, func(t *testing.T) {
			h := setup(t)
			switch namespace {
			case "label":
				h.m.Label = "com.keyward.test"
			case "socket":
				h.m.Socket = filepath.Join(h.m.Home, "isolated.sock")
			case "service":
				h.m.Service = "isolated-test"
			}
			command := h.m.Command
			h.m.Command = func(program string, args ...string) error {
				if filepath.Base(program) == "launchctl" && args[0] == "print" && strings.HasSuffix(args[1], "/com.veilux-lab.keyward.homebrew") {
					return nil
				}
				return command(program, args...)
			}
			if _, err := h.m.Run("install"); err != nil {
				t.Fatalf("unrelated production job blocked isolated install: %v", err)
			}
		})
	}
}

func TestSignedEnsurePreservesAnIsolatedSocket(t *testing.T) {
	h := setup(t)
	h.m.Socket = filepath.Join(h.m.Home, "isolated.sock")
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	h.loaded = false
	h.m.Ready = func(string) error {
		if h.loaded {
			return nil
		}
		return errors.New("not running")
	}
	command := h.m.Command
	h.m.Command = func(program string, args ...string) error {
		if filepath.Base(program) == "launchctl" && args[0] == "print" && strings.HasSuffix(args[1], "/com.veilux-lab.keyward.homebrew") {
			return nil
		}
		return command(program, args...)
	}
	if err := h.m.Ensure(); err != nil {
		t.Fatalf("unrelated production job blocked isolated ensure: %v", err)
	}
}

func TestSignedEnsureRespectsDisableAndExplicitReenable(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Run("uninstall"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "disabled") || len(h.calls) != 0 {
		t.Fatalf("ensure after explicit signed stop: %v", err)
	}
	h.unsigned = true
	if _, err := h.m.Run("install"); err == nil {
		t.Fatal("unsigned reinstall succeeded")
	}
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("failed signed reinstall cleared disabled preference")
	}
	h.unsigned = false
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(startupDir(h.m.Home), "startup.disabled")); !os.IsNotExist(err) {
		t.Fatal("successful signed reinstall retained disabled preference")
	}
}

func TestSignedEnsureDoesNotRestartALoadedUnhealthyJob(t *testing.T) {
	h := setup(t)
	h.loaded = true
	h.m.StartupTimeout = 40 * time.Millisecond
	h.m.Ready = func(string) error { return errors.New("not responding") }
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "service install") {
		t.Fatalf("loaded unhealthy signed job: %v", err)
	}
	for _, call := range h.calls {
		if !strings.HasPrefix(call, "launchctl print ") {
			t.Fatalf("ensure changed an unhealthy loaded job: %s", call)
		}
	}
}

func TestSignedEnsureRejectsUnsafeInstalledConfiguration(t *testing.T) {
	for _, unsafe := range []string{"malformed", "wrong binary", "program override", "bundle program override", "plist link", "binary link", "signature"} {
		t.Run(unsafe, func(t *testing.T) {
			h := setup(t)
			if _, err := h.m.Run("install"); err != nil {
				t.Fatal(err)
			}
			h.loaded = false
			h.calls = nil
			switch unsafe {
			case "malformed":
				os.WriteFile(h.plist(), []byte("<plist><dict>DO_NOT_SHOW_INPUT"), 0o600)
			case "wrong binary":
				content, err := os.ReadFile(h.plist())
				if err != nil {
					t.Fatal(err)
				}
				var installed, development bytes.Buffer
				xml.EscapeText(&installed, []byte(h.binary()))
				xml.EscapeText(&development, []byte(h.m.Executable))
				os.WriteFile(h.plist(), bytes.Replace(content, installed.Bytes(), development.Bytes(), 1), 0o600)
			case "program override", "bundle program override":
				content, err := os.ReadFile(h.plist())
				if err != nil {
					t.Fatal(err)
				}
				field := "Program"
				if unsafe == "bundle program override" {
					field = "BundleProgram"
				}
				var development bytes.Buffer
				xml.EscapeText(&development, []byte(h.m.Executable))
				override := "<key>" + field + "</key><string>" + development.String() + "</string>"
				os.WriteFile(h.plist(), bytes.Replace(content, []byte("<key>ProgramArguments</key>"), []byte(override+"<key>ProgramArguments</key>"), 1), 0o600)
			case "plist link":
				victim := filepath.Join(t.TempDir(), "plist")
				os.Rename(h.plist(), victim)
				os.Symlink(victim, h.plist())
			case "binary link":
				os.Remove(h.binary())
				os.Symlink(h.m.Executable, h.binary())
			case "signature":
				h.unsigned = true
			}
			err := h.m.Ensure()
			if err == nil || strings.Contains(err.Error(), "DO_NOT_SHOW_INPUT") {
				t.Fatalf("unsafe configuration: %v", err)
			}
			if strings.Contains(strings.Join(h.calls, "\n"), "bootstrap") {
				t.Fatal("unsafe configuration reached bootstrap")
			}
			if strings.Contains(unsafe, "override") && strings.Contains(strings.Join(h.calls, "\n"), "codesign") {
				t.Fatal("executable override reached codesign")
			}
		})
	}
}

func TestHomebrewEnsurePropagatesFailureWithoutRepeatedRestarts(t *testing.T) {
	h := brewSetup(t)
	h.fail = true
	if err := h.m.Ensure(); err == nil {
		t.Fatal("startup command failure was ignored")
	}
	h.fail = false
	command := h.m.Command
	h.m.Command = func(program string, args ...string) error {
		err := command(program, args...)
		if program == h.m.Brew && args[1] == "start" {
			h.mu.Lock()
			h.ready = false
			h.mu.Unlock()
		}
		return err
	}
	h.calls = nil
	for range 2 {
		if err := h.m.Ensure(); err == nil {
			t.Fatal("loaded unhealthy service reported ready")
		}
	}
	calls := strings.Join(h.calls, "\n")
	if strings.Count(calls, "brew services start ") != 1 || strings.Contains(calls, "restart") || strings.Contains(calls, "stop") {
		t.Fatalf("automatic retry changed a loaded service: %s", calls)
	}
}
