package cli

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// mcp shows each MCP server that would receive a cap:// reference; wrap runs
// them through keyward and unwrap reverses it. wrap skips a server whose URL reads
// a migrated secret not yet in a command line, unless given --allow-command-line,
// which the ledger then remembers for it.
// Claude Code's servers change through its own CLI after a yes, but not one that
// holds a credential, which that CLI would get in its command line; others are
// printed, because their tools cannot make the change without losing settings.
// Another Claude Code project's servers are named with its folder, where its CLI
// changes them, unless the folder is gone.
func (c *CLI) mcp(args []string) int {
	switch {
	case len(args) > 0 && args[0] == "wrap":
		fs := flag.NewFlagSet("mcp wrap", flag.ContinueOnError)
		fs.SetOutput(c.Stderr)
		allow := fs.Bool("allow-command-line", false, "also wrap a server whose URL reads a migrated secret, which mcp-remote gets in its command line")
		names, err := parse(fs, args[1:])
		if err != nil {
			return exitUsage
		}
		return c.mcpChange(true, *allow, names)
	case len(args) > 0 && args[0] == "unwrap":
		return c.mcpChange(false, false, args[1:])
	case len(args) != 0:
		fmt.Fprintln(c.Stderr, "usage: keyward mcp [wrap [--allow-command-line] | unwrap] [server...]")
		return exitUsage
	}
	findings, elsewhere, allowed, passed, gone, errs := c.mcpFindings()
	c.reportUnreadable(errs)
	if note := c.skippedNote(gone); note != "" {
		fmt.Fprintln(c.Stdout, note)
	}
	if len(findings) == 0 && len(elsewhere) == 0 {
		fmt.Fprintln(c.Stdout, "No MCP server needs a change.")
	}
	if len(findings) > 0 {
		fmt.Fprintf(c.Stdout, "%s.\n", strings.Join(mcpProblems(findings), ".\n"))
		changes := slices.ContainsFunc(findings, func(f mcpconfig.Finding) bool { return f.Suggestion != "" })
		if changes {
			fmt.Fprintln(c.Stdout, "Run each through keyward like this, so only that server gets its secrets:")
		}
		c.printFindings(findings, "uses")
		if changes {
			fmt.Fprint(c.Stdout, "\nkeyward mcp wrap makes these changes, through each tool's own command where it can.\n")
			for _, f := range findings {
				if addsURLExposure(f) {
					fmt.Fprintf(c.Stdout, "It skips %s unless given --allow-command-line, as its URL reads %s.\n", f.Name, strings.Join(f.InURL, ", "))
				}
				if fields := c.heldCredentials(f); len(fields) > 0 {
					fmt.Fprintf(c.Stdout, "It skips %s until the credential in its %s is moved out, as claude mcp add-json would get it in its command line.\n", f.Name, strings.Join(fields, ", "))
				}
			}
			fmt.Fprint(c.Stdout, "If mcp-remote reports a certificate error behind a corporate proxy, add\n"+
				"NODE_EXTRA_CA_CERTS to that server's env, pointing at your trusted certificates.\n")
		}
	}
	if len(elsewhere) > 0 {
		if len(findings) > 0 {
			fmt.Fprintln(c.Stdout)
		}
		c.printElsewhere(elsewhere)
	}
	if len(allowed) > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, "\n"+allowedProblem(len(allowed))+":"))
		for _, f := range allowed {
			fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("  %s (%s, %s): %s.", f.Name, f.Client, c.tilde(f.Config), urlWarning(f))))
		}
	}
	if len(passed) > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, "\n"+passedProblem(len(passed))+":"))
		for _, f := range passed {
			passes, it := "passes "+f.Passed[0]+" as an argument", "it"
			if len(f.Passed) > 1 {
				passes, it = "passes "+strings.Join(f.Passed, ", ")+" as arguments", "them"
			}
			fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("  %s (%s, %s): its script %s; pass %s in env instead, if the server reads %s from there.", f.Name, f.Client, c.tilde(f.Config), passes, it, it)))
		}
	}
	if len(findings) > 0 || len(elsewhere) > 0 {
		return exitFailure
	}
	return exitOK
}

// allowedProblem counts the servers whose URL puts a secret in mcp-remote's
// command line, as the user allowed.
func allowedProblem(n int) string {
	return fmt.Sprintf("%d MCP server(s) put a secret from their URL in a command line, as allowed with --allow-command-line", n)
}

// allow records that the user allows f's URL to put its secrets in mcp-remote's
// command line.
func (c *CLI) allow(f mcpconfig.Finding) error {
	if c.Ledger.Path == "" {
		return nil
	}
	return c.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: f.Config, Name: f.Name, Text: strings.Join(f.InURL, ",")})
}

// printElsewhere names the servers of other Claude Code projects that need a
// change, which wrap makes only in the project's folder.
func (c *CLI) printElsewhere(elsewhere []mcpconfig.Finding) {
	fmt.Fprintf(c.Stdout, "%d MCP server(s) in other Claude Code projects need a change; run keyward mcp wrap in the project's folder:\n", len(elsewhere))
	for _, f := range elsewhere {
		fmt.Fprintf(c.Stdout, "  %s  %s\n", f.Name, c.tilde(f.Project))
	}
}

func (c *CLI) mcpChange(wrap, allowCommandLine bool, names []string) int {
	command := "keyward mcp unwrap"
	findings, errs := c.mcpUndo()
	var elsewhere []mcpconfig.Finding
	var gone []string
	if wrap {
		command = "keyward mcp wrap"
		findings, elsewhere, _, _, gone, errs = c.mcpFindings()
	}
	c.reportUnreadable(errs)
	if note := c.skippedNote(gone); note != "" {
		fmt.Fprintln(c.Stdout, note)
	}
	if len(names) > 0 {
		for _, name := range names {
			named := func(f mcpconfig.Finding) bool { return f.Name == name }
			if slices.ContainsFunc(findings, named) {
				continue
			}
			if i := slices.IndexFunc(elsewhere, named); i >= 0 {
				return c.fail("%s: %s is a server of the Claude Code project in %s; run %s there", command, name, c.tilde(elsewhere[i].Project), command)
			}
			return c.fail("%s: no server named %q needs this change", command, name)
		}
		findings = slices.DeleteFunc(findings, func(f mcpconfig.Finding) bool { return !slices.Contains(names, f.Name) })
		elsewhere = nil
	}
	if len(elsewhere) > 0 {
		c.printElsewhere(elsewhere)
		if len(findings) > 0 {
			fmt.Fprintln(c.Stdout)
		}
	}
	if len(findings) == 0 {
		if len(elsewhere) > 0 {
			return exitFailure
		}
		if wrap {
			fmt.Fprintln(c.Stdout, "No MCP server needs a change.")
		} else {
			fmt.Fprintln(c.Stdout, "No MCP server starts through keyward.")
		}
		return exitOK
	}

	claude, haveClaude := c.findClaude()
	var viaClaude, manual []mcpconfig.Finding
	skipped := false
	for _, f := range findings {
		reason := skipReason(f, allowCommandLine)
		throughClaude := f.Client == "Claude Code" && haveClaude && c.Interactive
		if reason == "" && throughClaude {
			if fields := c.heldCredentials(f); len(fields) > 0 {
				reason = credentialsReason(fields) + ", then run " + command + " again"
			}
		}
		switch {
		case reason != "":
			fmt.Fprintln(c.Stdout, c.out(yellow, "Skipped "+f.Name+": "+reason+"."))
			skipped = true
		case f.Suggestion == "":
			// It runs through keyward already, so allowing it changes no config.
			if err := c.allow(f); err != nil {
				return c.fail("%s: %v", command, err)
			}
			fmt.Fprintln(c.Stdout, c.out(yellow, "Allowed "+f.Name+" to keep "+strings.Join(f.InURL, ", ")+" from its URL in mcp-remote's command line; "+
				"keyward mcp and doctor list it as a warning from now on."))
		case throughClaude:
			viaClaude = append(viaClaude, f)
		default:
			manual = append(manual, f)
		}
	}
	verb := "uses"
	if !wrap {
		verb = "reads"
	}
	// Unwrapped, a server reads its client's environment, which holds references
	// until the files are restored, and lacks a variable no file sets.
	restoreFirst := func() {
		if !wrap {
			fmt.Fprint(c.Stdout, "\nThose variables must hold real values again, so restore the files that set\n"+
				"them first, for example: keyward restore ~/.zshrc.\n")
			for _, u := range unsetIn(findings, c.variableFiles()) {
				fmt.Fprintln(c.Stdout, c.out(yellow, "Warning: "+u.Name+": "+u.fix()+"."))
			}
		}
	}
	if len(manual) > 0 {
		rerun := command
		if allowCommandLine {
			rerun += " --allow-command-line"
		}
		fmt.Fprintln(c.Stdout, c.manualReason(manual, haveClaude, rerun))
		c.printFindings(manual, verb)
		for _, f := range manual {
			if allowCommandLine && addsURLExposure(f) {
				if err := c.allow(f); err != nil {
					return c.fail("%s: %v", command, err)
				}
			}
		}
		if len(viaClaude) == 0 {
			restoreFirst()
		}
	}
	if len(viaClaude) == 0 {
		if len(manual) > 0 || skipped || len(elsewhere) > 0 {
			return exitFailure
		}
		return exitOK
	}

	fmt.Fprintf(c.Stdout, "\nClaude Code (%s): change %d server(s):\n", claude.Path, len(viaClaude))
	for _, f := range viaClaude {
		for _, line := range claude.Commands(f) {
			fmt.Fprintf(c.Stdout, "  %s\n", line)
		}
		if w := urlWarning(f); w != "" {
			fmt.Fprintln(c.Stdout, c.out(yellow, "  Warning: "+w+"."))
		}
	}
	restoreFirst()
	if ok, err := c.ask("Run these commands?"); err != nil || !ok {
		return c.cancel("Nothing was changed.")
	}
	failed := len(manual) > 0 || skipped || len(elsewhere) > 0
	for _, f := range viaClaude {
		err := claude.Apply(f)
		if err == nil {
			err = c.recordServer(wrap, f)
		}
		if err == nil && allowCommandLine && addsURLExposure(f) {
			err = c.allow(f)
		}
		if err != nil {
			fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("  %s: %v", f.Name, err)))
			failed = true
			continue
		}
		fmt.Fprintln(c.Stdout, c.out(green, "  ✓ "+f.Name))
	}
	fmt.Fprintln(c.Stdout, "\nRestart Claude Code to use the changed servers.")
	if failed {
		return exitFailure
	}
	return exitOK
}

// manualReason says why these changes are printed rather than made.
func (c *CLI) manualReason(manual []mcpconfig.Finding, haveClaude bool, command string) string {
	clients := map[string]bool{}
	for _, f := range manual {
		clients[f.Client] = true
	}
	var reasons []string
	if clients["Claude Code"] {
		switch {
		case !haveClaude:
			reasons = append(reasons, "claude was not found, or cannot add a server from JSON")
		case !c.Interactive:
			reasons = append(reasons, "keyward edits Claude Code only when run in a terminal, after a yes; run "+command+" in one")
		}
	}
	if clients["Codex"] {
		reasons = append(reasons, "Codex's mcp command cannot keep env_vars and tool settings")
	}
	if clients["Cursor"] {
		reasons = append(reasons, "Cursor has no command for this")
	}
	return "Change these yourself (" + strings.Join(reasons, "; ") + "):"
}

func (c *CLI) printFindings(findings []mcpconfig.Finding, verb string) {
	for _, f := range findings {
		reason := verb + " " + strings.Join(f.Vars, ", ")
		switch {
		case len(f.Exposed) > 0:
			reason = "exposes " + strings.Join(f.Exposed, ", ")
		case len(f.Unresolved) > 0:
			references := "reference"
			if len(f.Unresolved) > 1 {
				references += "s"
			}
			reason = "would receive the cap:// " + references + " in " + strings.Join(f.Unresolved, ", ") + ", which keyward run is not told to resolve"
		case len(f.InArgs) > 0:
			reason = "reads " + strings.Join(f.InArgs, ", ") + " in its arguments, which keyward run does not resolve"
		}
		fmt.Fprintf(c.Stdout, "\n%s\n  %s (%s, %s)\n", c.out(bold, f.Name), reason, f.Client, c.tilde(f.Config))
		if w := urlWarning(f); w != "" {
			fmt.Fprintln(c.Stdout, c.out(yellow, "  Warning: "+w+"."))
		}
		note := f.Note
		if f.Suggestion != "" {
			fmt.Fprintf(c.Stdout, "\n%s\n", indent(f.Suggestion, "    "))
		} else if !f.ByHand {
			note += " If you accept that, run keyward mcp wrap --allow-command-line " + f.Name + "."
		}
		fmt.Fprintf(c.Stdout, "\n  %s\n", c.tilde(note))
	}
}

// urlWarning says what in f's URL may be a secret, which wrapping puts where
// other programs can read it, or is empty if nothing.
func urlWarning(f mcpconfig.Finding) string {
	const exposed = ", and mcp-remote puts the URL in its command line, which any process can read, and in its log; "
	switch {
	case len(f.InURL) > 0:
		return "its URL holds " + strings.Join(f.InURL, ", ") + exposed + "use header authentication if the server supports it"
	case f.WrittenInURL:
		return "its URL may hold a secret in plaintext" + exposed + "move any secret there to a header if the server supports it"
	}
	return ""
}

// addsURLExposure reports whether wrapping f would put a secret from its URL in
// mcp-remote's command line. One that runs through keyward has it there already.
func addsURLExposure(f mcpconfig.Finding) bool {
	return len(f.InURL) > 0 && len(f.Exposed) == 0
}

// skipReason says why wrap leaves f as it is, or is empty if it does not.
func skipReason(f mcpconfig.Finding, allowCommandLine bool) string {
	switch {
	case f.ByHand:
		return strings.TrimSuffix(f.Note, ".")
	case f.Suggestion == "" && !allowCommandLine:
		return "it already runs through keyward, but " + urlWarning(f) + ", or, if you accept that, run keyward mcp wrap --allow-command-line " + f.Name
	case addsURLExposure(f) && !allowCommandLine:
		return urlWarning(f) + ", or, if you accept that, run keyward mcp wrap --allow-command-line " + f.Name
	}
	return ""
}

// heldCredentials names the fields of f that hold a credential claude mcp add-json
// would get in its command line, were f changed through it, which wrap, unwrap and
// uninstall therefore do not do.
func (c *CLI) heldCredentials(f mcpconfig.Finding) []string {
	if f.Client != "Claude Code" || f.Suggestion == "" {
		return nil
	}
	return mcpconfig.Claude{Home: c.Home, Workdir: c.Workdir}.Credentials(f)
}

// credentialsReason says why a change is not made through claude mcp add-json.
func credentialsReason(fields []string) string {
	holds, it := "holds a credential", "it"
	if len(fields) > 1 {
		holds, it = "hold credentials", "them"
	}
	return "its " + strings.Join(fields, ", ") + " " + holds + ", and claude mcp add-json would get " + it +
		" in its command line, where any process can read " + it + "; move " + it + " out first, as keyward doctor says"
}

// mcpProblems counts findings by kind: the fix is the same, the reason is not.
func mcpProblems(findings []mcpconfig.Finding) []string {
	exposed := 0
	for _, f := range findings {
		if len(f.Exposed) > 0 {
			exposed++
		}
	}
	var problems []string
	if n := len(findings) - exposed; n > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) would receive cap:// references instead of values", n))
	}
	if exposed > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) put a secret in a command line, which any process can read", exposed))
	}
	return problems
}

func (c *CLI) reportUnreadable(errs []error) {
	for _, err := range errs {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not read an MCP config, so it was not checked: %v", err)))
	}
}

// recordServer keeps the ledger in step: a wrapped server is recorded so
// uninstall reverts it, an unwrapped one is forgotten. A project server's record
// names its folder's .mcp.json, which uninstall reads wherever it runs.
func (c *CLI) recordServer(wrap bool, f mcpconfig.Finding) error {
	if c.Ledger.Path == "" {
		return nil
	}
	path := filepath.Join(c.Home, ".claude.json")
	if f.Scope == "project" {
		path = f.Config
	}
	if !wrap {
		return errors.Join(c.Ledger.Remove(ledger.Server, path, f.Name), c.Ledger.Remove(ledger.Allowed, f.Config, f.Name))
	}
	return c.Ledger.Add(ledger.Record{Kind: ledger.Server, Path: path, Name: f.Name, Text: f.Scope})
}

func (c *CLI) findClaude() (mcpconfig.Claude, bool) {
	if c.LookPath == nil || c.RunTool == nil {
		return mcpconfig.Claude{}, false
	}
	path, err := c.LookPath("claude")
	if err != nil {
		return mcpconfig.Claude{}, false
	}
	claude, ok := mcpconfig.FindClaude(path, c.RunTool)
	claude.Home, claude.Workdir, claude.Keyward = c.Home, c.Workdir, c.Self
	return claude, ok
}

func (c *CLI) mcpUndo() ([]mcpconfig.Finding, []error) {
	if c.Home == "" {
		return nil, nil
	}
	servers, errs := mcpconfig.Load(c.Home, c.Workdir)
	return mcpconfig.Undo(servers), errs
}

// mcpFindings is checkServers for every server keyward reads.
func (c *CLI) mcpFindings() (here, elsewhere, allowed, passed []mcpconfig.Finding, gone []string, errs []error) {
	if c.Home == "" {
		return nil, nil, nil, nil, nil, nil
	}
	servers, errs := mcpconfig.LoadAll(c.Home, c.Workdir)
	here, elsewhere, allowed, passed, gone = c.checkServers(servers)
	return here, elsewhere, allowed, passed, gone, errs
}

// checkServers returns the servers that need a change, and apart from them those
// of other Claude Code projects, which wrap changes only in their folder, and the
// bridges that put only their URL's secrets in mcp-remote's command line, each
// allowed with --allow-command-line. Only header authentication would take those
// out, so keyward lists them as a warning, as it does those passed, whose script
// passes a secret to a program as an argument. gone names the projects whose
// servers it passes over, as their folders no longer exist.
func (c *CLI) checkServers(servers []mcpconfig.Server) (here, elsewhere, allowed, passed []mcpconfig.Finding, gone []string) {
	if c.Home == "" {
		return nil, nil, nil, nil, nil
	}
	var records []ledger.Record
	if c.Ledger.Path != "" {
		records, _ = c.Ledger.Records()
	}
	refs := mcpconfig.References(doctor.DefaultPaths(c.Home, c.Workdir))
	for _, f := range mcpconfig.Check(servers, refs) {
		i := slices.IndexFunc(records, func(r ledger.Record) bool {
			return r.Kind == ledger.Allowed && r.Path == f.Config && r.Name == f.Name
		})
		switch {
		case mcpconfig.Gone(f.Project):
			if !slices.Contains(gone, f.Project) {
				gone = append(gone, f.Project)
			}
		case f.Suggestion == "" && !f.ByHand && i >= 0 && !slices.ContainsFunc(f.Exposed, func(v string) bool { return !slices.Contains(strings.Split(records[i].Text, ","), v) }):
			allowed = append(allowed, f)
		case f.Project != "" && f.Project != c.Workdir:
			elsewhere = append(elsewhere, f)
		default:
			here = append(here, f)
		}
	}
	for _, f := range mcpconfig.Arguments(servers, refs) {
		if !mcpconfig.Gone(f.Project) {
			passed = append(passed, f)
		}
	}
	slices.Sort(gone)
	return here, elsewhere, allowed, passed, gone
}

// passedProblem counts the servers whose script passes a secret to a program as an
// argument.
func passedProblem(n int) string {
	return fmt.Sprintf("%d MCP server(s) pass a secret to a program as an argument, which any process can read in its command line", n)
}

// skippedNote names the Claude Code projects whose servers were passed over, as
// their folders no longer exist, and says how to remove the servers, or is empty.
func (c *CLI) skippedNote(gone []string) string {
	if len(gone) == 0 {
		return ""
	}
	folders := make([]string, len(gone))
	for i, dir := range gone {
		folders[i] = c.tilde(dir)
	}
	return "Skipped Claude Code projects whose folders no longer exist: " + strings.Join(folders, ", ") + ". Their MCP servers can be removed from " +
		c.tilde(filepath.Join(c.Home, ".claude.json")) + " by hand, with Claude Code closed."
}

func (c *CLI) tilde(s string) string {
	if c.Home == "" {
		return s
	}
	return strings.ReplaceAll(s, c.Home+"/", "~/")
}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}
