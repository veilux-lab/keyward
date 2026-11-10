package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// mcp shows each MCP server that would receive a cap:// reference; wrap runs
// them through keyward and unwrap reverses it. wrap skips a server whose URL or
// arguments would put a migrated secret in a command line, which keyward run
// refuses, unless given --allow-command-line: it then gives the server's keyward
// run that option, and the ledger remembers it. A change keyward run would still
// refuse is never shown as the fix, nor marked done.
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
		allow := fs.Bool("allow-command-line", false, "also wrap a server that would put a migrated secret in a command line, from its URL or as an argument, and let its keyward run start it")
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
	findings, elsewhere, allowed, gone, errs := c.mcpFindings(false)
	c.reportUnreadable(errs)
	if note := c.skippedNote(gone); note != "" {
		fmt.Fprintln(c.Stdout, note)
	}
	if len(findings) == 0 && len(elsewhere) == 0 {
		fmt.Fprintln(c.Stdout, "No MCP server needs a change.")
	}
	if len(findings) > 0 {
		fmt.Fprintf(c.Stdout, "%s.\n", strings.Join(mcpProblems(findings), ".\n"))
		// Only a change keyward run would start is shown as the fix, and one to a
		// server it refuses already does not run that server through keyward.
		if slices.ContainsFunc(findings, func(f mcpconfig.Finding) bool { return f.Suggestion != "" && !refuses(f) && !f.Refused }) {
			fmt.Fprintln(c.Stdout, "Run each through keyward like this, so only that server gets its secrets:")
		}
		c.printFindings(findings, "uses", false)
		if slices.ContainsFunc(findings, func(f mcpconfig.Finding) bool { return f.Suggestion != "" && !addsCommandLine(f) }) {
			fmt.Fprint(c.Stdout, "\nkeyward mcp wrap makes these changes, through each tool's own command where it can.\n")
			for _, f := range findings {
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
		c.printElsewhere(elsewhere, "keyward mcp wrap")
	}
	if len(allowed) > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, "\n"+allowedProblem(allowed)+":"))
		for _, f := range allowed {
			fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("  %s (%s, %s): %s.", f.Name, f.Client, c.tilde(f.Config), strings.Join(warnings(f), "; "))))
		}
	}
	if note := c.cursorNote(); note != "" {
		fmt.Fprintln(c.Stdout, "\n"+note)
	}
	if len(findings) > 0 || len(elsewhere) > 0 {
		return exitFailure
	}
	return exitOK
}

// allowedProblem counts the servers that put a secret in a command line, from
// their URL or as an argument, or that start a script keyward run cannot read,
// as the user allowed.
func allowedProblem(allowed []mcpconfig.Finding) string {
	unread := 0
	for _, f := range allowed {
		if f.Unreadable {
			unread++
		}
	}
	what := "put a secret in a command line"
	switch unread {
	case 0:
	case len(allowed):
		what = "start unchecked"
	default:
		what += ", or start unchecked"
	}
	return fmt.Sprintf("%d MCP server(s) %s, as allowed with --allow-command-line", len(allowed), what)
}

// allow records that the user allows f to put the secrets of its CommandLine in a
// command line.
func (c *CLI) allow(f mcpconfig.Finding) error {
	if c.Ledger.Path == "" {
		return nil
	}
	return c.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: f.Config, Name: f.Name, Text: strings.Join(f.CommandLine, ",")})
}

// allows reports whether r records that the user allows its server to put each of
// secrets in a command line.
func allows(r ledger.Record, secrets []string) bool {
	return r.Kind == ledger.Allowed && !slices.ContainsFunc(secrets, func(v string) bool { return !slices.Contains(strings.Split(r.Text, ","), v) })
}

// printElsewhere names the servers of other Claude Code projects that need a
// change, which command makes only in the project's folder, and each keyward run
// refuses to start.
func (c *CLI) printElsewhere(elsewhere []mcpconfig.Finding, command string) {
	fmt.Fprintf(c.Stdout, "%d MCP server(s) in other Claude Code projects need a change; run %s in the project's folder:\n", len(elsewhere), command)
	for _, f := range elsewhere {
		refused := ""
		if f.Refused {
			refused = "  (keyward run refuses to start it)"
		}
		fmt.Fprintf(c.Stdout, "  %s  %s%s\n", f.Name, c.tilde(f.Project), refused)
	}
}

func (c *CLI) mcpChange(wrap, allowCommandLine bool, names []string) int {
	command := "keyward mcp unwrap"
	findings, errs := c.mcpUndo()
	var elsewhere []mcpconfig.Finding
	var gone []string
	if wrap {
		command = "keyward mcp wrap"
		findings, elsewhere, _, gone, errs = c.mcpFindings(allowCommandLine)
	}
	// To run again elsewhere, it keeps --allow-command-line, or would skip the same servers.
	rerun := command
	if allowCommandLine {
		rerun += " --allow-command-line"
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
				return c.fail("%s: %s is a server of the Claude Code project in %s; run %s there", command, name, c.tilde(elsewhere[i].Project), rerun)
			}
			return c.fail("%s: no server named %q needs this change", command, name)
		}
		findings = slices.DeleteFunc(findings, func(f mcpconfig.Finding) bool { return !slices.Contains(names, f.Name) })
		elsewhere = nil
	}
	if len(elsewhere) > 0 {
		c.printElsewhere(elsewhere, rerun)
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
		// What keyward run says follows a server skipped for it alone.
		refused := reason != "" && told(f)
		throughClaude := f.Client == "Claude Code" && haveClaude && c.Interactive
		if reason == "" && throughClaude {
			if fields := c.heldCredentials(f); len(fields) > 0 {
				reason = credentialsReason(fields) + ", then run " + command + " again"
			}
		}
		switch {
		case reason != "":
			fmt.Fprintln(c.Stdout, c.out(yellow, "Skipped "+f.Name+": "+reason+"."))
			if refused {
				c.printReasons(f, "  ")
				last := "To " + anyway(f) + "."
				if f.ByHand {
					last = f.Note
				}
				fmt.Fprintln(c.Stdout, c.out(yellow, "  "+last))
			}
			skipped = true
		case f.Suggestion == "":
			// Its keyward run has --allow-command-line already, so allowing it changes no config.
			if err := c.allow(f); err != nil {
				return c.fail("%s: %v", command, err)
			}
			kept := "keep " + strings.Join(f.CommandLine, ", ") + " in a command line"
			if f.Unreadable {
				kept = "start unchecked"
			}
			fmt.Fprintln(c.Stdout, c.out(yellow, "Allowed "+f.Name+" to "+kept+"; keyward mcp and doctor list it as a warning from now on."))
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
		fmt.Fprintln(c.Stdout, c.manualReason(manual, haveClaude, rerun))
		c.printFindings(manual, verb, allowCommandLine)
		for _, f := range manual {
			if allowCommandLine && len(f.CommandLine) > 0 {
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
		c.printReasons(f, "  ")
		for _, w := range warnings(f) {
			fmt.Fprintln(c.Stdout, c.out(yellow, "  Warning: "+w+"."))
		}
		if stillRefused(f) {
			fmt.Fprintln(c.Stdout, c.out(yellow, "  Warning: "+stillNote(f)))
		}
	}
	restoreFirst()
	if ok, err := c.ask("Run these commands?"); err != nil || !ok {
		return c.cancel("Nothing was changed.")
	}
	failed, changed := len(manual) > 0 || skipped || len(elsewhere) > 0, false
	for _, f := range viaClaude {
		err := claude.Apply(f)
		if err == nil {
			err = c.recordServer(wrap, f)
		}
		if err == nil && allowCommandLine && len(f.CommandLine) > 0 {
			err = c.allow(f)
		}
		switch {
		case err != nil:
			fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("  %s: %v", f.Name, err)))
			failed = true
		case stillRefused(f):
			fmt.Fprintln(c.Stdout, c.out(yellow, "  "+f.Name+" changed, but keyward run still refuses to start it. To "+anyway(f)+"."))
			failed = true
		default:
			fmt.Fprintln(c.Stdout, c.out(green, "  ✓ "+f.Name))
			changed = true
		}
	}
	if changed {
		fmt.Fprintln(c.Stdout, "\nRestart Claude Code to use the changed servers.")
	}
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

// printFindings prints each server's problem and its fix. allowCommandLine says
// wrap was given --allow-command-line; without it, a change that gives a server
// the option is one the user allowed before.
func (c *CLI) printFindings(findings []mcpconfig.Finding, verb string, allowCommandLine bool) {
	for _, f := range findings {
		reason := verb + " " + strings.Join(f.Vars, ", ")
		switch {
		case f.Refused:
			reason = "keyward run refuses to start it"
		case len(f.Exposed) > 0 && f.Unreadable:
			reason = "starts unchecked, as keyward run cannot read its script"
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
		c.printReasons(f, "    ")
		for _, w := range warnings(f) {
			fmt.Fprintln(c.Stdout, c.out(yellow, "  Warning: "+w+"."))
		}
		// A change keyward run would refuse, wrap makes only to a server it refuses
		// already, and is never shown as the fix.
		note := f.Note
		switch {
		case addsCommandLine(f):
			note = "keyward mcp wrap skips it. To " + anyway(f) + "."
		case f.Suggestion != "":
			fmt.Fprintf(c.Stdout, "\n%s\n", indent(f.Suggestion, "    "))
			switch {
			case stillRefused(f):
				note += " " + stillNote(f) + " To " + anyway(f) + "."
			case f.Refused && f.AllowCommandLine && !allowCommandLine:
				note = "You allowed this with --allow-command-line before, and keyward run now needs the option in its args. " + note
			}
		case refuses(f) && !f.ByHand:
			note += " To " + anyway(f) + "."
		case !f.ByHand:
			note += " If you accept that, run keyward mcp wrap --allow-command-line " + f.Name + "."
		}
		fmt.Fprintf(c.Stdout, "\n  %s\n", c.tilde(note))
	}
}

// stillRefused reports whether keyward run would refuse to start f's server once
// wrap changes it, as it would before. wrap makes such a change, as it rewrites
// an earlier keyward's bridge, but does not call it done.
func stillRefused(f mcpconfig.Finding) bool {
	return f.Suggestion != "" && refuses(f) && f.Refused
}

// stillNote says that keyward run would refuse to start f's server even once
// changed.
func stillNote(f mcpconfig.Finding) string {
	if f.Unreadable {
		return "keyward run would still refuse to start it once changed, as it cannot read its script."
	}
	return "keyward run would still refuse to start it once changed, as it would put " + strings.Join(f.CommandLine, ", ") + " in a command line."
}

// printReasons prints what keyward run says of f's server, each reason with its
// fix below it.
func (c *CLI) printReasons(f mcpconfig.Finding, indent string) {
	for _, r := range f.Reasons {
		fmt.Fprintln(c.Stdout, c.out(yellow, indent+r.Why))
		if r.Fix != "" {
			fmt.Fprintln(c.Stdout, c.out(yellow, indent+"  "+r.Fix))
		}
	}
}

// refuses reports whether keyward run would refuse to start f's server, as its
// change starts it, or as it is if there is none.
func refuses(f mcpconfig.Finding) bool {
	return len(f.CommandLine) > 0 && !f.AllowCommandLine
}

// told reports whether f's Reasons say why keyward run would refuse to start its
// server, as its warnings would otherwise.
func told(f mcpconfig.Finding) bool {
	return refuses(f) && len(f.Reasons) > 0
}

// anyway says how to start f's server though keyward run refuses it, which
// leaves its secrets where any process can read them, or for a script keyward
// run cannot read, unchecked, after a "to".
func anyway(f mcpconfig.Finding) string {
	if f.Unreadable {
		return "start it anyway, unchecked, run keyward mcp wrap --allow-command-line " + f.Name
	}
	it := "it"
	if len(f.CommandLine) > 1 {
		it = "them"
	}
	return "start it anyway, with " + strings.Join(f.CommandLine, ", ") + " in a command line, where any process can read " + it + ", run keyward mcp wrap --allow-command-line " + f.Name
}

// warnings say what f puts in a command line, as wrapped, from its URL and as an
// argument, where its Reasons do not.
func warnings(f mcpconfig.Finding) []string {
	if told(f) {
		return nil
	}
	var found []string
	for _, w := range []string{urlWarning(f), argWarning(f)} {
		if w != "" {
			found = append(found, w)
		}
	}
	return found
}

// urlWarning says what in f's URL may be a secret, which wrapping puts where
// other programs can read it, unless keyward run refuses it, or is empty if
// nothing.
func urlWarning(f mcpconfig.Finding) string {
	const exposed = ", and mcp-remote puts the URL in its command line, which any process can read, and in its log; "
	switch {
	case len(f.InURL) > 0 && refuses(f):
		return "its URL holds " + strings.Join(f.InURL, ", ") + ", and mcp-remote puts the URL in its command line and its log, so keyward run would refuse to start it; " +
			"use header authentication if the server supports it"
	case len(f.InURL) > 0:
		return "its URL holds " + strings.Join(f.InURL, ", ") + exposed + "use header authentication if the server supports it"
	case f.WrittenInURL:
		return "its URL may hold a secret in plaintext" + exposed + "move any secret there to a header if the server supports it"
	}
	return ""
}

// argWarning says which secrets f passes to a program as an argument, as its
// script does or, with a change, as wrapped it would, which any process can read
// in its command line unless keyward run refuses it, or is empty if none. Of a
// script keyward run cannot read, it says that it starts it unchecked.
func argWarning(f mcpconfig.Finding) string {
	passed := passedOf(f)
	switch {
	case len(passed) == 0:
		return ""
	case f.Unreadable:
		return "keyward run cannot read its script, so it starts it unchecked"
	}
	it, arguments := "it", " as an argument"
	if len(passed) > 1 {
		it, arguments = "them", " as arguments"
	}
	passes := "its script passes "
	if f.Suggestion != "" {
		passes = "wrapped, it would pass "
	}
	where := ", which any process can read in its command line"
	if refuses(f) {
		where = ", which keyward run refuses"
	}
	return passes + strings.Join(passed, ", ") + arguments + where + "; pass " + it + " in env instead, if the server reads " + it + " from there"
}

// passedOf names the secrets f's script puts in a command line other than in
// mcp-remote's URL: those it passes to a program as another argument.
func passedOf(f mcpconfig.Finding) []string {
	return slices.DeleteFunc(slices.Clone(f.CommandLine), func(v string) bool { return slices.Contains(f.InURL, v) })
}

// addsCommandLine reports whether wrapping f would put a secret in a command
// line, from its URL or as an argument, which keyward run refuses unless given
// --allow-command-line, and the user has not allowed, so wrap skips it. One
// keyward run refuses already is stillRefused instead.
func addsCommandLine(f mcpconfig.Finding) bool {
	return len(f.CommandLine) > 0 && !f.AllowCommandLine && !f.Refused
}

// skipReason says why wrap leaves f as it is, or is empty if it does not. Where
// told(f), what keyward run says of the server follows it.
func skipReason(f mcpconfig.Finding, allowCommandLine bool) string {
	switch {
	case f.ByHand && told(f):
		return "keyward run refuses to start it"
	case f.ByHand:
		return strings.TrimSuffix(f.Note, ".")
	case f.Suggestion == "" && f.Refused && !allowCommandLine:
		return "it already runs through keyward, but keyward run refuses to start it"
	case f.Suggestion == "" && !allowCommandLine:
		return "it already runs through keyward, but " + strings.Join(warnings(f), "; ") + ", or, if you accept that, run keyward mcp wrap --allow-command-line " + f.Name
	case addsCommandLine(f) && told(f):
		return "keyward run would refuse to start it as wrap would change it"
	case addsCommandLine(f):
		return strings.Join(warnings(f), "; ") + ", or, to " + anyway(f)
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
	refused, unread, exposed, unchecked := 0, 0, 0, 0
	for _, f := range findings {
		switch {
		case f.Refused && f.Unreadable:
			unread++
		case f.Refused:
			refused++
		case len(f.Exposed) > 0 && f.Unreadable:
			unchecked++
		case len(f.Exposed) > 0:
			exposed++
		}
	}
	var problems []string
	if n := len(findings) - refused - unread - exposed - unchecked; n > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) would receive cap:// references instead of values", n))
	}
	if refused > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) would put a secret in a command line, so keyward run refuses to start them", refused))
	}
	if unread > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) start a script keyward run cannot read, so it refuses to start them", unread))
	}
	if exposed > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) put a secret in a command line, which any process can read", exposed))
	}
	if unchecked > 0 {
		problems = append(problems, fmt.Sprintf("%d MCP server(s) start unchecked, as keyward run cannot read their script", unchecked))
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
func (c *CLI) mcpFindings(allowCommandLine bool) (here, elsewhere, allowed []mcpconfig.Finding, gone []string, errs []error) {
	if c.Home == "" {
		return nil, nil, nil, nil, nil
	}
	servers, errs := c.loadAll()
	here, elsewhere, allowed, gone = c.checkServers(servers, allowCommandLine)
	return here, elsewhere, allowed, gone, errs
}

// loadAll reads the MCP servers of every client keyward knows, in every Claude
// Code project and each folder the ledger names.
func (c *CLI) loadAll() ([]mcpconfig.Server, []error) {
	var records []ledger.Record
	if c.Ledger.Path != "" {
		records, _ = c.Ledger.Records()
	}
	return mcpconfig.LoadAll(c.Home, c.Workdir, ledgerFolders(records, c.Home)...)
}

// ledgerFolders names the project folders but home that records name servers
// in, which no tool may list: each whose .mcp.json wrap changed, and each whose
// Cursor server the user allowed to put a secret in a command line.
func ledgerFolders(records []ledger.Record, home string) []string {
	var folders []string
	for _, r := range records {
		dir := ""
		switch {
		case r.Kind == ledger.Server && filepath.Base(r.Path) == ".mcp.json":
			dir = filepath.Dir(r.Path)
		case r.Kind == ledger.Allowed && filepath.Base(r.Path) == "mcp.json" && filepath.Base(filepath.Dir(r.Path)) == ".cursor":
			dir = filepath.Dir(filepath.Dir(r.Path))
		}
		if dir != "" && dir != home {
			folders = append(folders, dir)
		}
	}
	return folders
}

// cursorNote says which Cursor projects keyward reads the servers of, as Cursor
// lists its projects nowhere keyward reads, or is empty if Cursor is not
// installed.
func (c *CLI) cursorNote() string {
	if info, err := os.Stat(filepath.Join(c.Home, ".cursor")); err != nil || !info.IsDir() {
		return ""
	}
	return "keyward reads a Cursor project's .cursor/mcp.json only in this folder and in those of Claude Code's projects, so run keyward mcp in any other folder you open in Cursor."
}

// checkServers returns the servers that need a change, and apart from them those
// of other Claude Code projects, which wrap changes only in their folder, and the
// servers that put a secret in a command line, from their URL or as an argument,
// as the user allowed with --allow-command-line. Only the server could take it
// out, so keyward lists those as a warning. gone names the projects whose
// servers it passes over, as their folders no longer exist. A change gives a
// server's keyward run --allow-command-line if the ledger records that the user
// allows it, or if allowCommandLine, as wrap is given it.
func (c *CLI) checkServers(servers []mcpconfig.Server, allowCommandLine bool) (here, elsewhere, allowed []mcpconfig.Finding, gone []string) {
	if c.Home == "" {
		return nil, nil, nil, nil
	}
	var records []ledger.Record
	if c.Ledger.Path != "" {
		records, _ = c.Ledger.Records()
	}
	allowedBefore := func(s mcpconfig.Server, secrets []string) bool {
		return slices.ContainsFunc(records, func(r ledger.Record) bool { return r.Path == s.Config && r.Name == s.Name && allows(r, secrets) })
	}
	allow := func(s mcpconfig.Server, secrets []string) bool { return allowCommandLine || allowedBefore(s, secrets) }
	refs := mcpconfig.References(doctor.DefaultPaths(c.Home, c.Workdir))
	for _, f := range mcpconfig.CheckAllowing(servers, refs, allow) {
		switch {
		case mcpconfig.Gone(f.Project):
			if !slices.Contains(gone, f.Project) {
				gone = append(gone, f.Project)
			}
		case f.Suggestion == "" && !f.ByHand && f.AllowCommandLine && allowedBefore(f.Server, f.CommandLine):
			allowed = append(allowed, f)
		case f.Project != "" && f.Project != c.Workdir:
			elsewhere = append(elsewhere, f)
		default:
			here = append(here, f)
		}
	}
	slices.Sort(gone)
	return here, elsewhere, allowed, gone
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
