package launchd

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// Homebrew leaves binaries and startup files under brew's management.
type Homebrew struct {
	Home, Brew     string
	UID            int
	StartupTimeout time.Duration
	Command        func(string, ...string) error
	Ready          func(string) error
}

func (h Homebrew) Run(action string) (string, error) {
	if !filepath.IsAbs(h.Home) || !filepath.IsAbs(h.Brew) || h.UID < 0 {
		return "", errors.New("Homebrew service needs absolute home and brew paths and a user ID")
	}
	m := h.manager()
	target := fmt.Sprintf("gui/%d/%s", h.UID, homebrewLabel)
	switch action {
	case "status":
		if m.command("/bin/launchctl", "print", target) != nil {
			return "Homebrew daemon is not loaded; start it with `keyward service install`", nil
		}
		if err := m.ready(); err != nil {
			return "", fmt.Errorf("Homebrew daemon is loaded but not responding; check Library/Logs/keyward/activity.jsonl: %w", err)
		}
		return "Homebrew daemon is running and starts automatically at login", nil
	case "install", "uninstall":
		state, err := lockStartup(h.Home, h.StartupTimeout)
		if err != nil {
			return "", err
		}
		defer state.close()
		if _, err := state.disabled(); err != nil {
			return "", err
		}
		if action == "uninstall" {
			if err := state.disable(); err != nil {
				return "", err
			}
			if err := m.command(h.Brew, "services", "stop", homebrewFormula); err != nil {
				return "", err
			}
			return "Homebrew startup stopped; the formula and Keychain items are kept", nil
		}
		signed := fmt.Sprintf("gui/%d/%s", h.UID, label)
		if m.command("/bin/launchctl", "print", signed) == nil {
			return "", errors.New("the signed Keyward login agent is loaded; use that installation's `keyward service uninstall` before starting the Homebrew daemon")
		}
		if m.command("/bin/launchctl", "print", target) != nil && m.ready() == nil {
			return "", errors.New("another Keyward daemon is already running; stop it before starting the Homebrew daemon")
		}
		if err := m.command(h.Brew, "services", "restart", homebrewFormula); err != nil {
			return "", err
		}
		if err := m.waitReady(); err != nil {
			return "", errors.Join(fmt.Errorf("Homebrew daemon did not become ready: %w", err), m.command(h.Brew, "services", "stop", homebrewFormula))
		}
		if err := state.enable(); err != nil {
			return "", err
		}
		return "Homebrew daemon starts now and at login; upgrades may require Keychain approval", nil
	default:
		return "", errors.New("usage: keyward service install|status|uninstall")
	}
}

func (h Homebrew) manager() Manager {
	return Manager{Home: h.Home, UID: h.UID, Command: h.Command, Ready: h.Ready, StartupTimeout: h.StartupTimeout}
}

// Ensure registers a new service once; existing jobs are left to launchd.
func (h Homebrew) Ensure() error {
	if !filepath.IsAbs(h.Home) || !filepath.IsAbs(h.Brew) || h.UID < 0 {
		return errors.New("Homebrew service needs absolute home and brew paths and a user ID")
	}
	m := h.manager()
	if m.ready() == nil {
		return nil
	}
	state, err := lockStartup(h.Home, h.StartupTimeout)
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
	domain := fmt.Sprintf("gui/%d/", h.UID)
	for _, job := range []string{label, homebrewLabel} {
		if m.command("/bin/launchctl", "print", domain+job) == nil {
			if err := m.waitReady(); err != nil {
				return fmt.Errorf("the Keyward login agent is loaded but not responding; use its installation's `keyward service install` and check Library/Logs/keyward/activity.jsonl: %w", err)
			}
			return nil
		}
	}
	if err := m.command(h.Brew, "services", "start", homebrewFormula); err != nil {
		return err
	}
	if err := m.waitReady(); err != nil {
		return fmt.Errorf("Homebrew daemon did not become ready; run `keyward service install` and check Library/Logs/keyward/activity.jsonl: %w", err)
	}
	return nil
}
