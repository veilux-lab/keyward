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

	"github.com/nwokolo24/keyward/internal/appbundle"
	"github.com/nwokolo24/keyward/internal/daemon"
	"github.com/nwokolo24/keyward/internal/vault"
)

const label = "com.nwokolo24.keyward"

type Manager struct {
	Home, Executable string
	Bundle           string
	Socket, Service  string
	UID              int
	// Label defaults to the production agent; integration tests use a distinct job.
	Label string
	// Command is injected so tests never register a real login agent.
	Command  func(program string, args ...string) error
	Ready    func(socket string) error
	Team     func(path string) (string, error)
	Register func(path string) error
}

func (m Manager) Run(action string) (string, error) {
	if !filepath.IsAbs(m.Home) || m.UID < 0 {
		return "", errors.New("service needs an absolute home directory and a user ID")
	}
	if m.Label == "" {
		m.Label = label
	}
	if strings.IndexFunc(m.Label, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_')
	}) >= 0 {
		return "", errors.New("invalid service label")
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
			return "", fmt.Errorf("login agent is loaded but the daemon is not responding; check Library/Logs/keyward/daemon.log: %w", err)
		}
		return "daemon is running and starts automatically at login", nil
	case "uninstall":
		if m.command("/bin/launchctl", "print", target) == nil {
			if err := m.command("/bin/launchctl", "bootout", target); err != nil {
				return "", err
			}
		}
		if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "automatic startup removed; the CLI and Keychain items are kept", nil
	case "install":
		return m.install(plist, domain, target)
	default:
		return "", errors.New("usage: keyward service install|status|uninstall")
	}
}

func (m Manager) install(plist, domain, target string) (string, error) {
	if !filepath.IsAbs(m.Executable) || (m.Socket != "" && !filepath.IsAbs(m.Socket)) {
		return "", errors.New("service needs absolute executable and socket paths")
	}
	if err := m.command("/usr/bin/codesign", "--verify", "--strict", "-R", `=anchor apple generic and identifier "com.nwokolo24.keyward"`, m.Executable); err != nil {
		return "", fmt.Errorf("install requires an Apple-signed keyward build: %w", err)
	}
	bundle := m.bundle()
	if err := m.command("/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", `=anchor apple generic and identifier "`+appbundle.ID+`"`, bundle); err != nil {
		return "", fmt.Errorf("install requires the signed Keyward.app companion: %w", err)
	}
	team := m.Team
	if team == nil {
		team = appbundle.Team
	}
	cliTeam, err := team(m.Executable)
	if err != nil {
		return "", err
	}
	appTeam, err := team(bundle)
	if err != nil {
		return "", err
	}
	if cliTeam == "" || cliTeam != appTeam {
		return "", errors.New("app and daemon must have the same signing team")
	}
	content, err := os.ReadFile(m.Executable)
	if err != nil {
		return "", err
	}
	binary := filepath.Join(m.Home, ".local", "bin", "keyward")
	logDir := filepath.Join(m.Home, "Library", "Logs", "keyward")
	logPath := filepath.Join(logDir, "daemon.log")
	for dir, mode := range map[string]os.FileMode{filepath.Dir(binary): 0o755, filepath.Dir(plist): 0o755, logDir: 0o700} {
		if err := os.MkdirAll(dir, mode); err != nil {
			return "", err
		}
	}
	info, err := os.Stat(logDir)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("daemon log directory must be private (mode 700)")
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if err := log.Close(); err != nil {
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
	appPath := filepath.Join(m.Home, "Applications", "Keyward.app")
	_, oldAppErr := os.Lstat(appPath)
	update, err := appbundle.Prepare(bundle, appPath)
	if err != nil {
		return "", err
	}
	defer update.Close()
	register := m.Register
	if register == nil {
		register = appbundle.Register
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
		err := errors.Join(oldBinary.restore(), oldPlist.restore(), update.Restore())
		if err == nil && loaded {
			err = m.command("/bin/launchctl", "bootstrap", domain, plist)
		}
		if oldAppErr == nil {
			err = errors.Join(err, register(appPath))
		}
		if err != nil {
			return "", errors.Join(cause, fmt.Errorf("restoring the prior installation: %w", err))
		}
		return "", cause
	}
	if err := update.Apply(); err != nil {
		return rollback(err)
	}
	if err := register(appPath); err != nil {
		return rollback(err)
	}
	if err := writeAtomic(binary, content, 0o755); err != nil {
		return rollback(err)
	}
	if err := writeAtomic(plist, []byte(m.configuration(binary, logPath)), 0o600); err != nil {
		return rollback(err)
	}
	if err := m.command("/bin/launchctl", "bootstrap", domain, plist); err != nil {
		return rollback(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		err := m.ready()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return rollback(fmt.Errorf("installed daemon did not start: %w", err))
		}
		time.Sleep(50 * time.Millisecond)
	}
	update.Commit()
	return fmt.Sprintf("installed %s and %s\ndaemon starts now and at login; log: %s", binary, appPath, logPath), nil
}

func (m Manager) bundle() string {
	if m.Bundle != "" {
		return m.Bundle
	}
	dir := filepath.Dir(m.Executable)
	if filepath.Base(dir) == "Helpers" && filepath.Base(filepath.Dir(dir)) == "Contents" {
		return filepath.Dir(filepath.Dir(dir))
	}
	companion := filepath.Join(dir, "Keyward.app")
	if _, err := os.Stat(companion); err == nil {
		return companion
	}
	return filepath.Join(m.Home, "Applications", "Keyward.app")
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

func (m Manager) configuration(binary, log string) string {
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
<key>AssociatedBundleIdentifiers</key><array><string>com.nwokolo24.keyward.app</string></array>
<key>ProgramArguments</key><array><string>%s</string><string>daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>2</integer>
<key>Umask</key><integer>63</integer>
<key>StandardErrorPath</key><string>%s</string>
<key>EnvironmentVariables</key><dict>
<key>KEYWARD_SOCKET</key><string>%s</string>
<key>KEYWARD_SERVICE</key><string>%s</string>
</dict>
</dict></plist>
`, escape(m.Label), escape(binary), escape(log), escape(socket), escape(service))
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
