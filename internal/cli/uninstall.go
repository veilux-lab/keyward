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
	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/restore"
)

// uninstall undoes everything keyward did, after one "yes": MCP servers and agent
// links first, then the values back into their files, then keyward itself. Each
// step finishes before the next starts and a rerun continues where one stopped,
// so a failure never leaves a reference with nothing to resolve it. Stored
// secrets are kept unless --purge is given.
func (c *CLI) uninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	purge := fs.Bool("purge", false, "also delete the vault and its key")
	dryRun := fs.Bool("dry-run", false, "show the plan, and stop")
	if rest, err := parse(fs, args); err != nil || len(rest) != 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward uninstall [--dry-run] [--purge]")
		return exitUsage
	}
	if len(c.DataDirs) == 0 || c.Service == nil || (*purge && c.PurgeVault == nil) {
		return c.fail("keyward uninstall: unavailable for isolated instances; stop that daemon yourself")
	}
	p, err := c.offboardingPlan()
	if err != nil {
		return c.fail("keyward uninstall: %v; nothing was changed", err)
	}
	// Purging while something still points at the vault would strand it for good.
	if *purge && (len(p.manual) > 0 || len(p.files.Skipped) > 0) {
		return c.fail("keyward uninstall --purge: these would still use stored secrets after uninstall. Change them first, then run it again:\n%s",
			p.leftForUser(c))
	}
	// Restoring needs every value; find out now, not halfway through.
	if len(p.files.Items) > 0 {
		secret, err := c.Store.Get(p.files.Items[0].Name)
		if err != nil {
			return c.fail("keyward uninstall: cannot read stored secrets, so no value could be put back: %v\n"+
				"  If the vault key was lost, restore it first: keyward recovery restore", err)
		}
		secret.Destroy()
	}

	fmt.Fprint(c.Stderr, c.uninstallPlan(p, *purge))
	if *dryRun {
		fmt.Fprintln(c.Stderr, c.errs(cyan, "Dry run: nothing was changed."))
		return exitOK
	}
	if _, err := fmt.Fprint(c.Stderr, c.errs(bold, `Type "yes" to remove Keyward:`)+" "); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward uninstall: could not read confirmation; nothing was removed")
	}
	if !ok {
		return c.cancel("Uninstall cancelled. Nothing was removed.")
	}
	stop := func(step string, err error) int {
		return c.fail("keyward uninstall: %s: %v\n  Nothing after this step was done. Fix it, then run keyward uninstall again to continue.", step, err)
	}

	// 1. MCP servers and agent links stop depending on keyward.
	for _, f := range p.viaClaude {
		if err := p.claude.Apply(f); err != nil {
			return stop("changing MCP server "+f.Name+" back", err)
		}
		_ = c.recordServer(false, f)
	}
	for _, r := range p.links {
		if err := agents.Unlink(r.Path, r.Text, r.Created); err != nil {
			return stop("removing the keyward line from "+c.tilde(r.Path), err)
		}
		_ = c.Ledger.Remove(ledger.Link, r.Path, "")
	}
	// 2. Values go back while the vault still exists.
	if len(p.files.Items) > 0 {
		r := p.files.Apply(c.Store)
		if len(r.Skipped) > 0 {
			var b strings.Builder
			for _, issue := range r.Skipped {
				fmt.Fprintf(&b, "\n    %s  %s", issue.Location(), issue.Reason)
			}
			return stop("putting values back", fmt.Errorf("%d could not be restored:%s", len(r.Skipped), b.String()))
		}
	}
	// 3. Keyward itself. Backup keys go while the daemon can still delete them.
	if _, err := removeBackups(c.Store, p.backups); err != nil {
		return stop("removing backups", err)
	}
	// Stop before deleting data: a running daemon would recreate it.
	if _, err := c.Service("uninstall"); err != nil {
		return stop("stopping the daemon", err)
	}
	if p.ownsAgentFile {
		if _, err := agents.Default(c.Home).Remove(); err != nil {
			return stop("removing "+agents.Display, err)
		}
	}
	for _, dir := range p.dirs {
		_ = os.Remove(dir) // only once empty
	}
	for _, dir := range c.DataDirs {
		err = errors.Join(err, removeAllBut(dir, c.KeepDir))
	}
	if err != nil {
		return stop("removing local data", err)
	}
	if *purge {
		if err := c.PurgeVault(); err != nil {
			return stop("deleting the vault", err)
		}
	}
	var lines []string
	if *purge {
		lines = append(lines, "✓ Keyward removed, with your stored secrets.")
	} else {
		lines = append(lines, "✓ Keyward removed. Stored secrets were kept; keyward uninstall --purge deletes them.")
	}
	// The package goes last, so a rerun is possible until everything else is done.
	if c.RemovePackage == nil {
		lines = append(lines, "  This is a development build: delete this keyward binary yourself.")
	} else {
		removed, err := c.RemovePackage()
		if err != nil {
			return c.fail("keyward uninstall: everything else was removed, but removing the package failed: %v", err)
		}
		lines = append(lines, "  "+removed)
	}
	if len(p.files.Items) > 0 {
		lines = append(lines, "  Open a new terminal, and restart any editor, so programs see the restored values.")
	}
	if left := c.residue(*purge, p); len(left) > 0 {
		lines = append(lines, "", "Still left; change these yourself:")
		for _, l := range left {
			lines = append(lines, "  "+l)
		}
	} else {
		lines = append(lines, "  Nothing keyward created is left.")
	}
	fmt.Fprintln(c.Stdout, paintLines(c.ColorOut, strings.Join(lines, "\n"), map[string]string{"✓": green}))
	return exitOK
}

// offboarding is everything uninstall will undo, gathered before anything changes.
type offboarding struct {
	files         *restore.Plan
	paths         []string
	claude        mcpconfig.Claude
	viaClaude     []mcpconfig.Finding
	manual        []mcpconfig.Finding
	links         []ledger.Record
	handLinks     []string
	backups       []backup.Backup
	dirs          []string
	ownsAgentFile bool
}

func (c *CLI) offboardingPlan() (offboarding, error) {
	var p offboarding
	records, err := c.Ledger.Records()
	if err != nil {
		return p, err
	}
	// Files: what the vault's provenance and the defaults show, plus every file
	// the ledger says migrate rewrote.
	inUse, err := doctor.InUse(c.Store, doctor.DefaultPaths(c.Home, c.Workdir))
	if err != nil {
		return p, fmt.Errorf("cannot check which files use keyward: %w", err)
	}
	quotes := map[string]map[string]string{}
	for _, r := range records {
		switch r.Kind {
		case ledger.Rewrite:
			inUse[r.Path] = max(inUse[r.Path], 1)
			quotes[r.Path] = r.Quotes
		case ledger.Link:
			p.links = append(p.links, r)
		case ledger.Dir:
			p.dirs = append(p.dirs, r.Path)
		}
	}
	servers, _ := c.mcpUndo()
	for _, s := range servers {
		// MCP configs are changed through their tools, never restored as text.
		file, _, _ := strings.Cut(s.Config, " (project ")
		delete(inUse, file)
	}
	for path := range inUse {
		p.paths = append(p.paths, path)
	}
	slices.Sort(p.paths)
	if p.files, err = restore.Read(c.Store, p.paths); err != nil {
		return p, err
	}
	p.files.Quotes = quotes

	var haveClaude bool
	p.claude, haveClaude = c.findClaude()
	for _, f := range servers {
		if f.Client == "Claude Code" && haveClaude && c.Interactive {
			p.viaClaude = append(p.viaClaude, f)
		} else {
			p.manual = append(p.manual, f)
		}
	}
	for _, config := range agents.Linked(c.Home) {
		if !slices.ContainsFunc(p.links, func(r ledger.Record) bool { return r.Path == config }) {
			p.handLinks = append(p.handLinks, config)
		}
	}
	if p.backups, err = c.knownBackups(); err != nil {
		return p, err
	}
	if c.Home != "" {
		st, _ := agents.Default(c.Home).Status()
		p.ownsAgentFile = st == agents.Current || st == agents.Outdated
	}
	return p, nil
}

func (c *CLI) uninstallPlan(p offboarding, purge bool) string {
	var b strings.Builder
	b.WriteString("keyward uninstall will:\n")
	step := 0
	next := func(format string, a ...any) {
		step++
		fmt.Fprintf(&b, "\n%d. "+format+"\n", append([]any{step}, a...)...)
	}
	if len(p.viaClaude) > 0 {
		next("Change %d Claude Code MCP server(s) back to start without keyward:", len(p.viaClaude))
		for _, f := range p.viaClaude {
			for _, line := range p.claude.Commands(f) {
				fmt.Fprintf(&b, "     %s\n", line)
			}
		}
	}
	if len(p.links) > 0 {
		next("Remove the line keyward added to each agent's instructions:")
		for _, r := range p.links {
			fmt.Fprintf(&b, "     %s  - %s\n", c.tilde(r.Path), r.Text)
		}
	}
	if len(p.files.Items) > 0 {
		counts := map[string]int{}
		for _, item := range p.files.Items {
			counts[item.File]++
		}
		next("Put %d value(s) back into these files. They hold plaintext secrets again, private to you:", len(p.files.Items))
		for _, path := range p.paths {
			if counts[path] > 0 {
				fmt.Fprintf(&b, "     %s (%d)\n", c.tilde(path), counts[path])
			}
		}
	}
	next("Remove keyward:")
	b.WriteString("     the daemon and its login startup\n")
	for _, dir := range c.DataDirs {
		fmt.Fprintf(&b, "     %s\n", c.tilde(dir))
	}
	if len(p.backups) > 0 {
		fmt.Fprintf(&b, "     %d backup(s) from migrate, and their keys\n", len(p.backups))
	}
	if p.ownsAgentFile {
		fmt.Fprintf(&b, "     %s, the instructions for AI agents\n", agents.Display)
	}
	if c.RemovePackage != nil {
		b.WriteString("     the keyward package\n")
	}
	if purge {
		b.WriteString("     your stored secrets: the vault and its Keychain key, permanently\n")
	} else {
		b.WriteString("   Kept: your stored secrets, in the encrypted vault and its Keychain key.\n")
	}
	if left := p.leftForUser(c); left != "" {
		fmt.Fprintf(&b, "\n%s\n%s", c.errs(yellow, "keyward cannot change these, so they stop working until you do:"), left)
	}
	b.WriteString("\n")
	return b.String()
}

// leftForUser lists what uninstall cannot change itself.
func (p offboarding) leftForUser(c *CLI) string {
	var b strings.Builder
	for _, f := range p.manual {
		fmt.Fprintf(&b, "  MCP server %s (%s, %s): keyward mcp unwrap shows the change\n", f.Name, f.Client, c.tilde(f.Config))
	}
	for _, config := range p.handLinks {
		fmt.Fprintf(&b, "  %s: remove the keyward.md line you added\n", c.tilde(config))
	}
	for _, issue := range p.files.Skipped {
		fmt.Fprintf(&b, "  %s: %s\n", c.tilde(issue.Location()), issue.Reason)
	}
	return b.String()
}

// residue checks the places keyward writes to and reports what is still there.
func (c *CLI) residue(purge bool, p offboarding) []string {
	var left []string
	exists := func(path string) bool { _, err := os.Lstat(path); return err == nil }
	for _, dir := range c.DataDirs {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case !purge && c.KeepDir != "" && (path == c.KeepDir || strings.HasPrefix(c.KeepDir, path+string(filepath.Separator))):
				if path == c.KeepDir {
					return filepath.SkipDir
				}
				return nil
			}
			left = append(left, c.tilde(path))
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
	}
	if c.Home != "" {
		if exists(agents.Default(c.Home).Path) {
			if st, _ := agents.Default(c.Home).Status(); st != agents.Foreign {
				left = append(left, agents.Display)
			}
		}
		agentsDir := filepath.Join(c.Home, "Library", "LaunchAgents")
		for _, name := range []string{"com.veilux-lab.keyward.dev.plist", "com.veilux-lab.keyward.homebrew.plist", "com.nwokolo24.keyward.plist"} {
			if path := filepath.Join(agentsDir, name); exists(path) {
				left = append(left, c.tilde(path))
			}
		}
	}
	for _, dir := range p.dirs {
		if exists(dir) {
			if entries, _ := os.ReadDir(dir); len(entries) == 0 {
				left = append(left, c.tilde(dir))
			}
		}
	}
	for _, path := range p.paths {
		if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), "cap://") {
			left = append(left, c.tilde(path)+" still has cap:// references")
		}
	}
	if servers, _ := c.mcpUndo(); len(servers) > 0 {
		for _, s := range servers {
			left = append(left, fmt.Sprintf("MCP server %s still starts through keyward (%s)", s.Name, c.tilde(s.Config)))
		}
	}
	for _, config := range agents.Linked(c.Home) {
		left = append(left, c.tilde(config)+" still mentions keyward.md")
	}
	return left
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
