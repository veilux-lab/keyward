// Package launchd installs the signed CLI and its per-user daemon.
package launchd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

const label = "com.nwokolo24.keyward"

type Manager struct {
	Home, Executable string
	Socket, Service  string
	UID              int
	LogConfig        *activity.Config
	// StartupTimeout bounds lock and readiness waits; zero uses five seconds.
	StartupTimeout time.Duration
	// Label defaults to the production agent; integration tests use a distinct job.
	Label string
	// Command is injected so tests never register a real login agent.
	Command func(program string, args ...string) error
	Ready   func(socket string) error
}

func (m Manager) Run(action string) (string, error) {
	var err error
	m, err = m.normalized()
	if err != nil {
		return "", err
	}
	plist := filepath.Join(m.Home, "Library", "LaunchAgents", m.Label+".plist")
	domain := fmt.Sprintf("gui/%d", m.UID)
	target := domain + "/" + m.Label
	switch action {
	case "status":
		if err := m.command("/bin/launchctl", "print", target); err != nil {
			return "daemon is not loaded; start it with `keyward service install`", nil
		}
		if err := m.ready(); err != nil {
			return "", fmt.Errorf("login agent is loaded but the daemon is not responding; check Library/Logs/keyward/activity.jsonl: %w", err)
		}
		return "daemon is running and starts automatically at login", nil
	case "install", "uninstall":
		state, err := lockStartup(m.Home, m.StartupTimeout)
		if err != nil {
			return "", err
		}
		defer state.close()
		if _, err := state.disabled(); err != nil {
			return "", err
		}
		if action == "install" {
			if m.defaultNamespace() && m.command("/bin/launchctl", "print", domain+"/"+homebrewLabel) == nil {
				return "", errors.New("the Homebrew Keyward login agent is loaded; stop it with that installation's `keyward service uninstall` before installing the signed daemon")
			}
			message, err := m.install(plist, domain, target)
			if err == nil {
				err = state.enable()
			}
			return message, err
		}
		// Record the opt-out before stopping, so a failed state write leaves startup intact.
		if err := state.disable(); err != nil {
			return "", err
		}
		if m.command("/bin/launchctl", "print", target) == nil {
			if err := m.command("/bin/launchctl", "bootout", target); err != nil {
				return "", err
			}
		}
		if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "automatic startup removed; the CLI and Keychain items are kept", nil
	default:
		return "", errors.New("usage: keyward service install|status|uninstall")
	}
}

func (m Manager) normalized() (Manager, error) {
	if !filepath.IsAbs(m.Home) || m.UID < 0 {
		return m, errors.New("service needs an absolute home directory and a user ID")
	}
	if m.Label == "" {
		m.Label = label
	}
	if strings.IndexFunc(m.Label, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_')
	}) >= 0 {
		return m, errors.New("invalid service label")
	}
	return m, nil
}

func (m Manager) defaultNamespace() bool {
	return (m.Label == "" || m.Label == label) && m.socket() == daemon.DefaultSocket(m.Home) &&
		(m.Service == "" || m.Service == vault.DefaultService)
}

// Ensure starts only an already installed daemon, never the caller's development build.
func (m Manager) Ensure() error {
	var err error
	m, err = m.normalized()
	if err != nil {
		return err
	}
	if m.Socket != "" && !filepath.IsAbs(m.Socket) {
		return errors.New("service needs an absolute socket path")
	}
	if m.ready() == nil {
		return nil
	}
	state, err := lockStartup(m.Home, m.StartupTimeout)
	if err != nil {
		return err
	}
	defer state.close()
	if m.ready() == nil {
		return nil
	}
	disabled, err := state.disabled()
	if err != nil {
		return err
	}
	if disabled {
		return errStartupDisabled
	}
	plist := filepath.Join(m.Home, "Library", "LaunchAgents", m.Label+".plist")
	domain := fmt.Sprintf("gui/%d", m.UID)
	target := domain + "/" + m.Label
	targets := []string{target}
	if m.defaultNamespace() {
		targets = append(targets, domain+"/"+homebrewLabel)
	}
	for _, loaded := range targets {
		if m.command("/bin/launchctl", "print", loaded) == nil {
			if err := m.waitReady(); err != nil {
				return fmt.Errorf("the Keyward login agent is loaded but not responding; use its installation's `keyward service install` and check Library/Logs/keyward/activity.jsonl: %w", err)
			}
			return nil
		}
	}
	binary := filepath.Join(m.Home, ".local", "bin", "keyward")
	if err := m.installedConfiguration(plist, binary); err != nil {
		return err
	}
	if err := m.command("/usr/bin/codesign", "--verify", "--strict", "-R", `=anchor apple generic and identifier "com.nwokolo24.keyward"`, binary); err != nil {
		return fmt.Errorf("the installed daemon must be Apple-signed; run `make install` or `keyward service install` with a signed build: %w", err)
	}
	if err := m.command("/bin/launchctl", "bootstrap", domain, plist); err != nil {
		return err
	}
	if err := m.waitReady(); err != nil {
		return fmt.Errorf("the installed daemon did not become ready; run `keyward service install` and check Library/Logs/keyward/activity.jsonl: %w", err)
	}
	return nil
}

func (m Manager) install(plist, domain, target string) (string, error) {
	if !filepath.IsAbs(m.Executable) || (m.Socket != "" && !filepath.IsAbs(m.Socket)) {
		return "", errors.New("service needs absolute executable and socket paths")
	}
	if err := m.command("/usr/bin/codesign", "--verify", "--strict", "-R", `=anchor apple generic and identifier "com.nwokolo24.keyward"`, m.Executable); err != nil {
		return "", fmt.Errorf("install requires an Apple-signed keyward build: %w", err)
	}
	content, err := os.ReadFile(m.Executable)
	if err != nil {
		return "", err
	}
	binary := filepath.Join(m.Home, ".local", "bin", "keyward")
	logConfig := activity.DefaultConfig(m.Home)
	if m.LogConfig != nil {
		logConfig = *m.LogConfig
	}
	logPath := filepath.Join(logConfig.Dir, "activity.jsonl")
	for dir, mode := range map[string]os.FileMode{filepath.Dir(binary): 0o755, filepath.Dir(plist): 0o755} {
		if err := os.MkdirAll(dir, mode); err != nil {
			return "", err
		}
	}
	log, err := activity.New(logConfig)
	if err != nil {
		return "", err
	}
	if err := log.Clean(); err != nil {
		return "", err
	}
	oldBinary, err := snapshot(binary)
	if err != nil {
		return "", err
	}
	oldPlist, err := snapshot(plist)
	if err != nil {
		return "", err
	}
	loaded := m.command("/bin/launchctl", "print", target) == nil
	if loaded {
		if err := m.command("/bin/launchctl", "bootout", target); err != nil {
			return "", err
		}
	}
	rollback := func(cause error) (string, error) {
		if m.command("/bin/launchctl", "print", target) == nil {
			if err := m.command("/bin/launchctl", "bootout", target); err != nil {
				return "", errors.Join(cause, err)
			}
		}
		err := errors.Join(oldBinary.restore(), oldPlist.restore())
		if err == nil && loaded {
			err = m.command("/bin/launchctl", "bootstrap", domain, plist)
		}
		if err != nil {
			return "", errors.Join(cause, fmt.Errorf("restoring the prior installation: %w", err))
		}
		return "", cause
	}
	if err := writeAtomic(binary, content, 0o755); err != nil {
		return rollback(err)
	}
	if err := writeAtomic(plist, []byte(m.configuration(binary, logConfig)), 0o600); err != nil {
		return rollback(err)
	}
	if err := m.command("/bin/launchctl", "bootstrap", domain, plist); err != nil {
		return rollback(err)
	}
	if err := m.waitReady(); err != nil {
		return rollback(fmt.Errorf("installed daemon did not start: %w", err))
	}
	return fmt.Sprintf("installed %s\ndaemon starts now and at login; log: %s", binary, logPath), nil
}

func (m Manager) socket() string {
	if m.Socket != "" {
		return m.Socket
	}
	return daemon.DefaultSocket(m.Home)
}

func (m Manager) ready() error {
	if m.Ready != nil {
		return m.Ready(m.socket())
	}
	return (&daemon.Client{Path: m.socket(), Timeout: 500 * time.Millisecond}).Ping()
}

func (m Manager) command(program string, args ...string) error {
	if m.Command != nil {
		return m.Command(program, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(program), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m Manager) configuration(binary string, config activity.Config) string {
	socket := m.socket()
	service := m.Service
	if service == "" {
		service = vault.DefaultService
	}
	escape := func(s string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>2</integer>
<key>Umask</key><integer>63</integer>
<key>StandardErrorPath</key><string>/dev/null</string>
<key>EnvironmentVariables</key><dict>
<key>KEYWARD_SOCKET</key><string>%s</string>
<key>KEYWARD_SERVICE</key><string>%s</string>
<key>KEYWARD_LOG_DIR</key><string>%s</string>
<key>KEYWARD_LOG_RETENTION_DAYS</key><string>%d</string>
<key>KEYWARD_LOG_MAX_MB</key><string>%d</string>
<key>KEYWARD_LOG_ROTATE_MB</key><string>%d</string>
</dict>
</dict></plist>
`, escape(m.Label), escape(binary), escape(socket), escape(service), escape(config.Dir), int64(config.Retention/(24*time.Hour)), config.MaxBytes>>20, config.RotateBytes>>20)
}

type savedFile struct {
	path    string
	content []byte
	mode    os.FileMode
	exists  bool
}

func snapshot(path string) (savedFile, error) {
	s := savedFile{path: path}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if !info.Mode().IsRegular() {
		return s, fmt.Errorf("refusing to replace non-regular file %s", path)
	}
	s.exists, s.mode = true, info.Mode().Perm()
	s.content, err = os.ReadFile(path)
	return s, err
}

func (s savedFile) restore() error {
	if s.exists {
		return writeAtomic(s.path, s.content, s.mode)
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Rename preserves a running executable's inode while installing the next build.
func writeAtomic(path string, content []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".keyward-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(content); err == nil {
		err = f.Chmod(mode)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
