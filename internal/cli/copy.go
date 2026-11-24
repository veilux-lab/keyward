package cli

import (
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/vault"
)

// clipboardTime is how long a copied value stays on the clipboard.
const clipboardTime = 30 * time.Second

// copyToClipboard puts a stored value on the clipboard for the user to paste. It
// needs a terminal, so a pipe cannot answer its prompt, and reads the value only
// after a "yes".
func (c *CLI) copyToClipboard(args []string) int {
	if !c.Interactive {
		c.refused = true
		fmt.Fprintln(c.Stderr, c.errs(red, "keyward copy: run it yourself in a terminal, not through an AI agent or a pipe, which could read the value."))
		return exitUsage
	}
	if len(args) != 1 {
		fmt.Fprint(c.Stderr, "usage: keyward copy <name>\n")
		return exitUsage
	}
	name, code := c.storedSecret("copy", args[0])
	if code != exitOK {
		return code
	}
	seconds := int(clipboardTime / time.Second)
	if _, err := fmt.Fprintf(c.Stderr, "\nCopy %s to the clipboard? Any app can read it there until it clears, in %d seconds.\n  %s\n\n  Enter a value: ",
		name, seconds, c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord))); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward copy: could not read confirmation")
	}
	if !ok {
		return c.cancel("Aborted. Nothing was copied.")
	}
	secret, err := c.Store.Get(name)
	if err != nil {
		return c.fail("keyward copy: %v", err)
	}
	defer secret.Destroy()
	if !utf8.Valid(secret.Bytes()) {
		return c.fail("keyward copy: %s is not text, so it cannot go on the clipboard", name)
	}
	count, err := c.Clipboard(secret.Bytes())
	if err != nil {
		return c.fail("keyward copy: could not copy %s: %v", name, err)
	}
	if err := c.ClearClipboard(count, clipboardTime); err != nil {
		return c.fail("keyward copy: %s is on the clipboard, but it will not clear by itself: %v. Copy something else to replace it.", name, err)
	}
	fmt.Fprintf(c.Stdout, "Copied %s. The clipboard clears in %d seconds.\n", name, seconds)
	return exitOK
}

// storedSecret returns raw's canonical name if it is one of the user's stored
// secrets, or the exit code of the failure it reported. It reads names only, so a
// typo fails before anyone says yes to it. A backup's key is not one of the
// user's secrets, as keyward ls shows.
func (c *CLI) storedSecret(command, raw string) (string, int) {
	name, err := handle.Normalize(raw)
	if err != nil {
		return "", c.fail("keyward %s: %v", command, err)
	}
	entries, err := c.Store.Entries()
	if err != nil {
		return "", c.fail("keyward %s: %v", command, err)
	}
	if backup.IsKey(name) || !slices.ContainsFunc(entries, func(e vault.Entry) bool { return e.Name == name }) {
		return "", c.fail("keyward %s: no secret is named %s; keyward ls lists them", command, name)
	}
	return name, exitOK
}
