package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/veilux-lab/keyward/internal/vault"
)

// recovery shows the vault key as a code, or restores a lost key from one. Without
// the key every stored secret is unreadable, and nothing else holds a copy.
func (c *CLI) recovery(args []string) int {
	if len(args) != 1 || (args[0] != "show" && args[0] != "restore") {
		fmt.Fprintln(c.Stderr, "usage: keyward recovery show | keyward recovery restore")
		return exitUsage
	}
	if c.Recovery == nil {
		return c.fail("keyward recovery: unavailable without the keyward daemon")
	}
	if args[0] == "show" {
		return c.showRecovery()
	}
	return c.restoreRecovery()
}

// showRecovery needs a terminal on both ends, so a pipe cannot capture the code.
// An agent could open a terminal itself, so the refusal sends it to the user.
func (c *CLI) showRecovery() int {
	if !c.Interactive {
		return c.fail("keyward recovery show: run it in Terminal.app, so the code is not captured by a pipe or an AI agent. An AI agent must ask the user to run it.")
	}
	if _, err := fmt.Fprintf(c.Stderr, "\nShow the code that decrypts every stored secret?\n"+
		"  Anyone with it and a copy of your vault can read them all.\n"+
		"  Store it in a password manager, not in a file. %s\n\n  Enter a value: ",
		c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord))); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward recovery show: could not read confirmation")
	}
	if !ok {
		return c.cancel("Aborted. Nothing was shown.")
	}
	key, err := c.Recovery.ExportKey()
	if err != nil {
		return c.fail("keyward recovery show: %v", err)
	}
	defer key.Destroy()
	fmt.Fprintf(c.Stdout, "\n  %s\n\nIf the vault key is ever lost, restore it with: keyward recovery restore\n", vault.RecoveryCode(key.Bytes()))
	if c.RecoveryMarker != "" {
		// Only stops the reminders; losing it costs a reminder, not a secret.
		_ = os.WriteFile(c.RecoveryMarker, nil, 0o600)
	}
	return exitOK
}

// restoreRecovery reads the code like a secret, never from argv.
func (c *CLI) restoreRecovery() int {
	raw, err := c.ReadSecret()
	if err != nil {
		return c.fail("keyward recovery restore: reading the code: %v", err)
	}
	key, err := vault.ParseRecoveryCode(string(raw))
	clear(raw)
	if err != nil {
		return c.fail("keyward recovery restore: %v", err)
	}
	secret := vault.NewSecret(key)
	clear(key)
	defer secret.Destroy()
	changed, err := c.Recovery.RestoreKey(secret)
	if err != nil {
		return c.fail("keyward recovery restore: %v", err)
	}
	if changed {
		fmt.Fprintln(c.Stdout, c.out(green, "Vault key restored; your stored secrets are readable again."))
	} else {
		fmt.Fprintln(c.Stdout, "The vault key was already correct; nothing changed.")
	}
	return exitOK
}

// recoveryReminder names Terminal.app and sends an agent to the user, since
// following it in an editor's terminal shows the code where agents can read it.
const recoveryReminder = "Save a recovery code for your vault, in case its key is ever lost: run keyward recovery show in Terminal.app. An AI agent must ask the user to run it."

// remindRecovery nudges until a recovery code has been shown once.
func (c *CLI) remindRecovery() {
	if c.RecoveryMarker == "" {
		return
	}
	if _, err := os.Stat(c.RecoveryMarker); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(c.Stdout, c.out(yellow, "\n"+recoveryReminder))
	}
}
