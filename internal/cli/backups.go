package cli

import (
	"errors"
	"flag"
	"fmt"
	"slices"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/doctor"
)

func (c *CLI) backups(args []string) int {
	if len(args) == 0 || args[0] == "ls" && len(args) == 1 {
		return c.listBackups()
	}
	if args[0] != "rm" {
		fmt.Fprintln(c.Stderr, "usage: keyward backups [ls] | keyward backups rm (--all | <file>...)")
		return exitUsage
	}
	fs := flag.NewFlagSet("backups rm", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	all := fs.Bool("all", false, "remove every backup")
	files, err := parse(fs, args[1:])
	if err != nil {
		return exitUsage
	}
	if *all == (len(files) != 0) {
		fmt.Fprintln(c.Stderr, "usage: keyward backups rm (--all | <file>...)")
		return exitUsage
	}
	var found []backup.Backup
	if *all {
		found, err = c.knownBackups()
	} else {
		for _, file := range files {
			mine, ferr := c.Backups.ForFile(file)
			found, err = append(found, mine...), errors.Join(err, ferr)
		}
	}
	if err != nil {
		return c.fail("keyward backups: %v", err)
	}
	removed, err := removeBackups(found)
	fmt.Fprintln(c.Stdout, c.out(green, fmt.Sprintf("Removed %d plaintext backup(s).", removed)))
	if err != nil {
		return c.fail("keyward backups: %v", err)
	}
	return exitOK
}

func (c *CLI) listBackups() int {
	found, err := c.knownBackups()
	if err != nil {
		return c.fail("keyward backups: %v", err)
	}
	if len(found) == 0 {
		fmt.Fprintln(c.Stdout, "No plaintext backups.")
		return exitOK
	}
	fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("%d plaintext backup(s) hold secrets as they were before migration:", len(found))))
	for _, b := range found {
		fmt.Fprintf(c.Stdout, "  %s  %s\n      %s\n", b.Created.Local().Format("2006-01-02 15:04"), b.Original, b.Path)
	}
	fmt.Fprintln(c.Stdout, "\nRemove them once the migrated files work:\n  keyward backups rm <file>...\n  keyward backups rm --all")
	return exitOK
}

// knownBackups adds legacy backups beside the files doctor reads by default.
func (c *CLI) knownBackups() ([]backup.Backup, error) {
	found, err := c.Backups.List()
	if err != nil {
		return nil, err
	}
	for _, path := range doctor.DefaultPaths(c.Home, c.Workdir) {
		mine, err := c.Backups.ForFile(path)
		if err != nil {
			return nil, err
		}
		for _, b := range mine {
			if b.Legacy {
				found = append(found, b)
			}
		}
	}
	return found, nil
}

func removeBackups(found []backup.Backup) (int, error) {
	var errs error
	removed := 0
	for _, b := range found {
		if err := backup.Remove(b); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		removed++
	}
	return removed, errs
}

// removeRestoredBackups drops backups only for files restored without a skip.
func (c *CLI) removeRestoredBackups(restored, skipped []string) {
	for _, file := range slices.Compact(slices.Sorted(slices.Values(restored))) {
		if slices.Contains(skipped, file) {
			continue
		}
		found, err := c.Backups.ForFile(file)
		if err == nil {
			var removed int
			removed, err = removeBackups(found)
			if removed > 0 {
				fmt.Fprintln(c.Stdout, c.out(green, fmt.Sprintf("Removed %d plaintext backup(s) of %s; the file holds the values again.", removed, file)))
			}
		}
		if err != nil {
			fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not remove every backup of %s: %v. See keyward backups.", file, err)))
		}
	}
}
