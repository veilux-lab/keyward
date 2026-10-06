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
	paths, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(paths) == 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward restore [--dry-run] <file>...")
		return exitUsage
	}
	p, err := restore.Read(c.Store, paths)
	if err != nil {
		return c.fail("keyward restore: %v", err)
	}
	if _, err := io.WriteString(c.Stdout, paintLines(c.ColorOut, p.Preview(), map[string]string{"  skip ": yellow})); err != nil {
		return c.fail("keyward restore: could not print the plan; no files were changed")
	}
	if *dryRun || len(p.Items) == 0 {
		if *dryRun {
			fmt.Fprintln(c.Stdout, c.out(cyan, "Dry run: no secret values were read and no files were changed."))
		} else {
			fmt.Fprintln(c.Stdout, "Nothing to restore.")
		}
		if len(p.Skipped) != 0 {
			return exitFailure
		}
		return exitOK
	}
	if _, err := fmt.Fprintf(c.Stderr, "\nRestore %d value(s) into the files listed above?\n  These files will contain plaintext secrets again and will be private to your user.\n  Keychain entries will be kept. %s\n\n  Enter a value: ", len(p.Items), c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord))); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward restore: could not read confirmation; no files were changed")
	}
	if !ok {
		return c.cancel("Aborted. No secret values were read and no files were changed.")
	}
	r := p.Apply(c.Store)
	for _, item := range r.Restored {
		fmt.Fprintln(c.Stdout, c.out(green, fmt.Sprintf("  restored %s:%d  %s <- cap://%s", item.File, item.Line, item.Variable, item.Name)))
	}
	for _, issue := range r.Skipped {
		fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("  skipped %s  %s", issue.Location(), issue.Reason)))
	}
	fmt.Fprintf(c.Stdout, "\nRestored %d value(s); %d item(s) skipped. Keychain entries were kept.\n", len(r.Restored), len(r.Skipped))
	var restored, skipped []string
	for _, item := range r.Restored {
		restored = append(restored, item.File)
	}
	for _, issue := range r.Skipped {
		skipped = append(skipped, issue.File)
	}
	c.removeRestoredBackups(restored, skipped)
	if len(r.Skipped) != 0 {
		return exitFailure
	}
	return exitOK
}
