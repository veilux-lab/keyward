package launchd

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// Homebrew leaves binaries and startup files under brew's management.
type Homebrew struct {
	Home, Brew string
	UID        int
	Command    func(string, ...string) error
	Ready      func(string) error
}

func (h Homebrew) Run(action string) (string, error) {
	if !filepath.IsAbs(h.Home) || !filepath.IsAbs(h.Brew) || h.UID < 0 {
		return "", errors.New("Homebrew service needs absolute home and brew paths and a user ID")
	}
	m := Manager{Home: h.Home, UID: h.UID, Command: h.Command, Ready: h.Ready}
	target := fmt.Sprintf("gui/%d/com.veilux-lab.keyward.homebrew", h.UID)
	const formula = "veilux-lab/keyward/keyward"
	switch action {
	case "status":
		if m.command("/bin/launchctl", "print", target) != nil {
			return "Homebrew daemon is not loaded; start it with `keyward service install`", nil
		}
		if err := m.ready(); err != nil {
			return "", fmt.Errorf("Homebrew daemon is loaded but not responding; check Library/Logs/keyward/activity.jsonl: %w", err)
		}
		return "Homebrew daemon is running and starts automatically at login", nil
	case "uninstall":
		if err := m.command(h.Brew, "services", "stop", formula); err != nil {
			return "", err
		}
		return "Homebrew startup stopped; the formula and Keychain items are kept", nil
	case "install":
		signed := fmt.Sprintf("gui/%d/%s", h.UID, label)
		if m.command("/bin/launchctl", "print", signed) == nil {
			return "", errors.New("the signed Keyward login agent is loaded; use that installation's `keyward service uninstall` before starting the Homebrew daemon")
		}
		if m.command("/bin/launchctl", "print", target) != nil && m.ready() == nil {
			return "", errors.New("another Keyward daemon is already running; stop it before starting the Homebrew daemon")
		}
		if err := m.command(h.Brew, "services", "restart", formula); err != nil {
			return "", err
		}
		for deadline := time.Now().Add(5 * time.Second); ; {
			if err := m.ready(); err == nil {
				break
			} else if time.Now().After(deadline) {
				return "", errors.Join(fmt.Errorf("Homebrew daemon did not become ready: %w", err), m.command(h.Brew, "services", "stop", formula))
			}
			time.Sleep(50 * time.Millisecond)
		}
		return "Homebrew daemon starts now and at login; upgrades may require Keychain approval", nil
	default:
		return "", errors.New("usage: keyward service install|status|uninstall")
	}
}
