package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/vault"
)

func (c *CLI) backups(args []string) int {
	if len(args) == 0 || args[0] == "ls" && len(args) == 1 {
		return c.listBackups()
	}
	if args[0] == "recover" {
		return c.recoverBackup(args[1:])
	}
	if args[0] != "rm" {
		fmt.Fprintln(c.Stderr, "usage: keyward backups [ls] | keyward backups rm (--all | <file>...) | keyward backups recover <file>")
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
	removed, err := removeBackups(c.Store, found)
	fmt.Fprintln(c.Stdout, c.out(green, fmt.Sprintf("Removed %d backup(s).", removed)))
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
		fmt.Fprintln(c.Stdout, "No backups.")
		return exitOK
	}
	fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("%d backup(s) hold secrets as they were before migration:", len(found))))
	for _, b := range found {
		// Older releases wrote plaintext, which any tool reading the file can see.
		kind := c.out(yellow, "plaintext")
		if b.Encrypted() {
			kind = "encrypted"
		}
		fmt.Fprintf(c.Stdout, "  %s  %s  %s\n      %s\n", b.Created.Local().Format("2006-01-02 15:04"), kind, b.Original, b.Path)
	}
	fmt.Fprintln(c.Stdout, "\nRemove them once the migrated files work:\n  keyward backups rm <file>...\n  keyward backups rm --all\n"+
		"To get a file's original back first: keyward backups recover <file>")
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

func removeBackups(store vault.Store, found []backup.Backup) (int, error) {
	var errs error
	removed := 0
	for _, b := range found {
		if err := backup.Remove(store, b); err != nil {
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
			removed, err = removeBackups(c.Store, found)
			if removed > 0 {
				fmt.Fprintln(c.Stdout, c.out(green, fmt.Sprintf("Removed %d backup(s) of %s; the file holds the values again.", removed, file)))
			}
		}
		if err != nil {
			fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not remove every backup of %s: %v. See keyward backups.", file, err)))
		}
	}
}

// recoverBackup writes a file's newest backup beside it, never over it, so edits
// made since migrating survive. It asks first: the result is plaintext again.
func (c *CLI) recoverBackup(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Stderr, "usage: keyward backups recover <file>")
		return exitUsage
	}
	found, err := c.Backups.ForFile(args[0])
	if err != nil {
		return c.fail("keyward backups recover: %v", err)
	}
	if len(found) == 0 {
		return c.fail("keyward backups recover: no backup of %s", args[0])
	}
	latest := slices.MaxFunc(found, func(a, b backup.Backup) int { return a.Created.Compare(b.Created) })
	out := latest.Original + ".keyward-recovered-" + time.Now().UTC().Format("20060102T150405Z")
	if _, err := fmt.Fprintf(c.Stderr, "\nWrite the backup of %s from %s to %s?\n  That file will hold the old values in plaintext. %s\n\n  Enter a value: ",
		latest.Original, latest.Created.Local().Format("2006-01-02 15:04"), out, c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord))); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward backups recover: could not read confirmation; nothing was written")
	}
	if !ok {
		return c.cancel("Aborted. Nothing was written.")
	}
	data, err := backup.Open(c.Store, latest)
	if err != nil {
		return c.fail("keyward backups recover: %v", err)
	}
	defer data.Destroy()
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return c.fail("keyward backups recover: %v", err)
	}
	_, err = f.Write(data.Bytes())
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(out)
		return c.fail("keyward backups recover: writing %s: %v", out, err)
	}
	fmt.Fprintln(c.Stdout, c.out(green, "Recovered the original to "+out))
	fmt.Fprintln(c.Stdout, "  It holds plaintext secrets. Delete it once you have what you need.")
	return exitOK
}
