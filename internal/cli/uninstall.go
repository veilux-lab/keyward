package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// uninstall removes Keyward's startup, local data, and package. Stored secrets are
// kept unless --purge is given, so reinstalling brings everything back.
func (c *CLI) uninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	purge := fs.Bool("purge", false, "also delete the vault and its key")
	if rest, err := parse(fs, args); err != nil || len(rest) != 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward uninstall [--purge]")
		return exitUsage
	}
	if len(c.DataDirs) == 0 || c.Service == nil || (*purge && c.PurgeVault == nil) {
		return c.fail("keyward uninstall: unavailable for isolated instances; stop that daemon yourself")
	}
	inUse, err := doctor.InUse(c.Store, doctor.DefaultPaths(c.Home, c.Workdir))
	if err != nil && *purge {
		return c.fail("keyward uninstall: cannot check which files still use keyward, so nothing was purged: %v", err)
	}
	// restore cannot rewrite MCP configs; keyward mcp --undo covers those.
	servers, _ := c.mcpUndo()
	for _, s := range servers {
		// A project server's Config names its project after the file.
		file, _, _ := strings.Cut(s.Config, " (project ")
		delete(inUse, file)
	}
	using := restoreList(inUse)
	mcpUsing := mcpList(c, servers)
	// Purging now would leave these files pointing at secrets that no longer exist.
	if *purge && (using != "" || mcpUsing != "") {
		return c.fail("keyward uninstall --purge: these still use stored secrets. Change them back first, then run it again:\n%s%s", using, mcpUsing)
	}
	found, err := c.knownBackups()
	if err != nil {
		return c.fail("keyward uninstall: %v", err)
	}
	var plan strings.Builder
	fmt.Fprintf(&plan, "%s\n\n", c.errs(yellow, "Warning: after uninstall, cap:// references in your files stop resolving."))
	if using != "" {
		fmt.Fprintf(&plan, "These files still use keyward. Cancel and restore them first to put the values back:\n%s\n", using)
	}
	if mcpUsing != "" {
		fmt.Fprintf(&plan, "These MCP servers start through keyward and stop working without it. Cancel and change them back first:\n%s\n", mcpUsing)
	}
	if using == "" && mcpUsing == "" {
		plan.WriteString("No file keyward knows of uses it. Restore any other file with cap:// references first: keyward restore <file>\n\n")
	}
	plan.WriteString("This removes:\n  the daemon and its login startup\n")
	for _, dir := range c.DataDirs {
		fmt.Fprintf(&plan, "  %s\n", dir)
	}
	if len(found) > 0 {
		fmt.Fprintf(&plan, "  %d backup(s) from migrate, and their keys\n", len(found))
	}
	agentFile := agents.Default(c.Home)
	ownsAgentFile := false
	if c.Home != "" {
		st, _ := agentFile.Status()
		ownsAgentFile = st == agents.Current || st == agents.Outdated
	}
	if ownsAgentFile {
		fmt.Fprintf(&plan, "  %s, the instructions for AI agents\n", agents.Display)
	}
	if c.RemovePackage != nil {
		plan.WriteString("  the keyward package\n")
	}
	if *purge {
		plan.WriteString("  your stored secrets: the vault and its Keychain key, permanently\n\n")
	} else {
		plan.WriteString("Kept: your stored secrets, in the encrypted vault and its Keychain key. To delete them too, use keyward uninstall --purge.\n\n")
	}
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

	// Backup keys go while the daemon can still delete them.
	if _, err := removeBackups(c.Store, found); err != nil {
		return c.fail("keyward uninstall: removing backups: %v; nothing else was removed", err)
	}
	// Stop before deleting data: a running daemon would recreate it.
	if _, err := c.Service("uninstall"); err != nil {
		return c.fail("keyward uninstall: %v; nothing else was removed", err)
	}
	for _, dir := range c.DataDirs {
		err = errors.Join(err, removeAllBut(dir, c.KeepDir))
	}
	if ownsAgentFile {
		_, rmErr := agentFile.Remove()
		err = errors.Join(err, rmErr)
	}
	if *purge {
		err = errors.Join(err, c.PurgeVault())
	}
	if err != nil {
		return c.fail("keyward uninstall: removing local data: %v; the package was kept", err)
	}
	var lines []string
	lines = append(lines, "✓ Keyward removed. Stored secrets were kept.")
	if c.RemovePackage == nil {
		lines = append(lines, "  This is a development build: delete this keyward binary yourself.")
	} else {
		removed, err := c.RemovePackage()
		if err != nil {
			return c.fail("keyward uninstall: local data was removed, but removing the package failed: %v", err)
		}
		lines = append(lines, "  "+removed)
	}
	if c.Home != "" {
		// Their files are the user's to edit; keyward only says where.
		for _, config := range agents.Linked(c.Home) {
			lines = append(lines, "  Remove the keyward.md line from "+config)
		}
	}
	fmt.Fprintln(c.Stdout, paintLines(c.ColorOut, strings.Join(lines, "\n"), map[string]string{"✓": green}))
	return exitOK
}

// removeAllBut deletes dir, except keep and the folders leading to it.
func removeAllBut(dir, keep string) error {
	rel, err := filepath.Rel(dir, keep)
	if keep == "" || err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return os.RemoveAll(dir)
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.Name() == first {
			if path != keep {
				errs = append(errs, removeAllBut(path, keep))
			}
			continue
		}
		errs = append(errs, os.RemoveAll(path))
	}
	return errors.Join(errs...)
}

// mcpList names each MCP server still starting through keyward, and the command that
// shows how to change it back.
func mcpList(c *CLI, servers []mcpconfig.Finding) string {
	if len(servers) == 0 {
		return ""
	}
	var b strings.Builder
	for _, s := range servers {
		fmt.Fprintf(&b, "  %s (%s, %s)\n", s.Name, s.Client, c.tilde(s.Config))
	}
	b.WriteString("  keyward mcp --undo shows the definition for each\n")
	return b.String()
}

// restoreList renders each file still using keyward with the command that restores it.
func restoreList(inUse map[string]int) string {
	files := make([]string, 0, len(inUse))
	for file := range inUse {
		files = append(files, file)
	}
	slices.Sort(files)
	var b strings.Builder
	for _, file := range files {
		fmt.Fprintf(&b, "  %s (%d reference(s)): keyward restore %s\n", file, inUse[file], file)
	}
	return b.String()
}
