package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// uninstall removes Keyward's startup, local data, and package, keeping Keychain items.
func (c *CLI) uninstall(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward uninstall")
		return exitUsage
	}
	if len(c.DataDirs) == 0 || c.Service == nil {
		return c.fail("keyward uninstall: unavailable for isolated instances; stop that daemon yourself")
	}
	found, err := c.knownBackups()
	if err != nil {
		return c.fail("keyward uninstall: %v", err)
	}
	var plan strings.Builder
	fmt.Fprintf(&plan, "%s\n\nThis removes:\n  the daemon and its login startup\n", c.errs(yellow, "Warning: after uninstall, cap:// references in your files stop resolving."))
	for _, dir := range c.DataDirs {
		fmt.Fprintf(&plan, "  %s\n", dir)
	}
	if len(found) > 0 {
		fmt.Fprintf(&plan, "  %d plaintext backup(s) from migrate\n", len(found))
	}
	if c.RemovePackage != nil {
		plan.WriteString("  the keyward package\n")
	}
	plan.WriteString("Kept: your Keychain items. Remove them first with keyward rm <name> if you want them gone.\n\n" +
		"To put secrets back into your files, cancel and run: keyward restore <file>...\n\n")
	if _, err := fmt.Fprint(c.Stderr, plan.String()+c.errs(bold, `Type "yes" to remove Keyward:`)+" "); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward uninstall: could not read confirmation; nothing was removed")
	}
	if !ok {
		return c.cancel("Uninstall cancelled. Nothing was removed.")
	}

	// Stop first: a running daemon would recreate what is deleted below.
	if _, err := c.Service("uninstall"); err != nil {
		return c.fail("keyward uninstall: %v; nothing else was removed", err)
	}
	_, err = removeBackups(found)
	for _, dir := range c.DataDirs {
		err = errors.Join(err, os.RemoveAll(dir))
	}
	if err != nil {
		return c.fail("keyward uninstall: removing local data: %v; the package was kept", err)
	}
	var lines []string
	lines = append(lines, "✓ Keyward removed. Keychain items were kept.")
	if c.RemovePackage == nil {
		lines = append(lines, "  This is a development build: delete this keyward binary yourself.")
	} else {
		removed, err := c.RemovePackage()
		if err != nil {
			return c.fail("keyward uninstall: local data was removed, but removing the package failed: %v", err)
		}
		lines = append(lines, "  "+removed)
	}
	fmt.Fprintln(c.Stdout, paintLines(c.ColorOut, strings.Join(lines, "\n"), map[string]string{"✓": green}))
	return exitOK
}
