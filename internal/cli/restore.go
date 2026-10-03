package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/veilux-lab/keyward/internal/restore"
)

func (c *CLI) restore(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	dryRun := fs.Bool("dry-run", false, "list references to restore without reading secret values")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward restore [--dry-run] <file>...")
		return exitUsage
	}
	p, err := restore.Read(c.Store, fs.Args())
	if err != nil {
		return c.fail("keyward restore: %v", err)
	}
	if _, err := io.WriteString(c.Stdout, p.Preview()); err != nil {
		return c.fail("keyward restore: could not print the plan; no files were changed")
	}
	if *dryRun || len(p.Items) == 0 {
		if *dryRun {
			fmt.Fprintln(c.Stdout, "Dry run: no secret values were read and no files were changed.")
		} else {
			fmt.Fprintln(c.Stdout, "Nothing to restore.")
		}
		if len(p.Skipped) != 0 {
			return exitFailure
		}
		return exitOK
	}
	if _, err := fmt.Fprintf(c.Stderr, "\nRestore %d value(s) into the files listed above?\n  These files will contain plaintext secrets again and will be private to your user.\n  Keychain entries will be kept. Only %q will be accepted.\n\n  Enter a value: ", len(p.Items), confirmWord); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward restore: could not read confirmation; no files were changed")
	}
	if !ok {
		return c.fail("Aborted. No secret values were read and no files were changed.")
	}
	r := p.Apply(c.Store)
	for _, item := range r.Restored {
		fmt.Fprintf(c.Stdout, "  restored %s:%d  %s <- cap://%s\n", item.File, item.Line, item.Variable, item.Name)
	}
	for _, issue := range r.Skipped {
		fmt.Fprintf(c.Stdout, "  skipped %s  %s\n", issue.Location(), issue.Reason)
	}
	fmt.Fprintf(c.Stdout, "\nRestored %d value(s); %d item(s) skipped. Keychain entries were kept.\n", len(r.Restored), len(r.Skipped))
	if len(r.Skipped) != 0 {
		return exitFailure
	}
	return exitOK
}
