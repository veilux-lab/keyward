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
			if stopped(h.Home) {
				return stoppedStatus, nil
			}
			return notRunningMessage, nil
		}
		if err := m.ready(); err != nil {
			return "", fmt.Errorf("Homebrew daemon is loaded but not responding; check Library/Logs/keyward/activity.jsonl: %w", err)
		}
		return runningMessage, nil
	case "start":
		if err := resume(h.Home, h.StartupTimeout); err != nil {
			return "", err
		}
		if err := h.Ensure(); err != nil {
			return "", err
		}
		return startedMessage, nil
	case "stop":
		state, err := lockStartup(h.Home, h.StartupTimeout)
		if err != nil {
			return "", err
		}
		defer state.close()
		if err := state.mark(stoppedMarker); err != nil {
			return "", err
		}
		// Unload without `brew services stop`, which would also cancel login startup.
		if m.command("/bin/launchctl", "print", target) == nil {
			if err := m.command("/bin/launchctl", "bootout", target); err != nil {
				return "", err
			}
		}
		return stoppedMessage, nil
	case "install", "uninstall":
		state, err := lockStartup(h.Home, h.StartupTimeout)
		if err != nil {
			return "", err
		}
		defer state.close()
		if _, err := state.marked(disabledMarker); err != nil {
			return "", err
		}
		if action == "uninstall" {
			if err := state.mark(disabledMarker); err != nil {
				return "", err
			}
			if err := m.command(h.Brew, "services", "stop", homebrewFormula); err != nil {
				return "", err
			}
			return uninstalledMessage, nil
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
		if err := errors.Join(state.unmark(disabledMarker), state.unmark(stoppedMarker)); err != nil {
			return "", err
		}
		return runningMessage + "\n  After an upgrade, macOS may ask once to let it read your Keychain items.", nil
	default:
		return "", errors.New("usage: keyward service install|start|stop|status|uninstall")
	}
}

// Remove uninstalls the formula and its tap, which brew cannot do from a formula.
func (h Homebrew) Remove() (string, error) {
	m := h.manager()
	if err := m.command(h.Brew, "uninstall", homebrewFormula); err != nil {
		return "", err
	}
	if err := m.command(h.Brew, "untap", "veilux-lab/keyward"); err != nil {
		return "", fmt.Errorf("the formula was removed, but untapping failed: %w", err)
	}
	return "Ran brew uninstall and brew untap veilux-lab/keyward.", nil
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
	if err := state.blocked(); err != nil {
		return err
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
