package cli

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// mcp shows each MCP server that would receive a cap:// reference; wrap runs
// them through keyward and unwrap reverses it. Claude Code's servers change
// through its own CLI after a yes; others are printed, because their tools
// cannot make the change without losing settings.
func (c *CLI) mcp(args []string) int {
	switch {
	case len(args) > 0 && args[0] == "wrap":
		return c.mcpChange(true, args[1:])
	case len(args) > 0 && args[0] == "unwrap":
		return c.mcpChange(false, args[1:])
	case len(args) != 0:
		fmt.Fprintln(c.Stderr, "usage: keyward mcp [wrap|unwrap] [server...]")
		return exitUsage
	}
	findings, errs := c.mcpFindings()
	c.reportUnreadable(errs)
	if len(findings) == 0 {
		fmt.Fprintln(c.Stdout, "No MCP server needs a change.")
		return exitOK
	}
	fmt.Fprintf(c.Stdout, "%d MCP server(s) would receive cap:// references instead of values.\n"+
		"Run each through keyward, so only that server gets its secrets:\n", len(findings))
	c.printFindings(findings, "uses")
	fmt.Fprint(c.Stdout, "\nkeyward mcp wrap makes these changes, through each tool's own command where it can.\n"+
		"If mcp-remote reports a certificate error behind a corporate proxy, add\n"+
		"NODE_EXTRA_CA_CERTS to that server's env, pointing at your trusted certificates.\n")
	return exitFailure
}

func (c *CLI) mcpChange(wrap bool, names []string) int {
	command := "keyward mcp unwrap"
	findings, errs := c.mcpUndo()
	if wrap {
		command = "keyward mcp wrap"
		findings, errs = c.mcpFindings()
	}
	c.reportUnreadable(errs)
	if len(names) > 0 {
		for _, name := range names {
			if !slices.ContainsFunc(findings, func(f mcpconfig.Finding) bool { return f.Name == name }) {
				return c.fail("%s: no server named %q needs this change", command, name)
			}
		}
		findings = slices.DeleteFunc(findings, func(f mcpconfig.Finding) bool { return !slices.Contains(names, f.Name) })
	}
	if len(findings) == 0 {
		if wrap {
			fmt.Fprintln(c.Stdout, "No MCP server needs a change.")
		} else {
			fmt.Fprintln(c.Stdout, "No MCP server starts through keyward.")
		}
		return exitOK
	}

	claude, haveClaude := c.findClaude()
	var viaClaude, manual []mcpconfig.Finding
	for _, f := range findings {
		if f.Client == "Claude Code" && haveClaude && c.Interactive {
			viaClaude = append(viaClaude, f)
		} else {
			manual = append(manual, f)
		}
	}
	verb := "uses"
	if !wrap {
		verb = "reads"
	}
	if len(manual) > 0 {
		fmt.Fprintln(c.Stdout, c.manualReason(manual, haveClaude, command))
		c.printFindings(manual, verb)
		if !wrap {
			fmt.Fprint(c.Stdout, "\nThose variables must hold real values again, so restore the files that set\n"+
				"them first, for example: keyward restore ~/.zshrc.\n")
		}
	}
	if len(viaClaude) == 0 {
		return exitFailure
	}

	fmt.Fprintf(c.Stdout, "\nClaude Code (%s): change %d server(s):\n", claude.Path, len(viaClaude))
	for _, f := range viaClaude {
		for _, line := range claude.Commands(f) {
			fmt.Fprintf(c.Stdout, "  %s\n", line)
		}
	}
	if ok, err := c.ask("Run these commands?"); err != nil || !ok {
		return c.cancel("Nothing was changed.")
	}
	failed := len(manual) > 0
	for _, f := range viaClaude {
		err := claude.Apply(f)
		if err == nil {
			err = c.recordServer(wrap, f)
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
		fmt.Fprintf(c.Stdout, "\n%s\n  %s %s (%s, %s)\n\n%s\n\n  %s\n",
			c.out(bold, f.Name), verb, strings.Join(f.Vars, ", "), f.Client, c.tilde(f.Config),
			indent(f.Suggestion, "    "), c.tilde(f.Note))
	}
}

func (c *CLI) reportUnreadable(errs []error) {
	for _, err := range errs {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not read an MCP config, so it was not checked: %v", err)))
	}
}

// recordServer keeps the ledger in step: a wrapped server is recorded so
// uninstall reverts it, an unwrapped one is forgotten.
func (c *CLI) recordServer(wrap bool, f mcpconfig.Finding) error {
	if c.Ledger.Path == "" {
		return nil
	}
	path := filepath.Join(c.Home, ".claude.json")
	if f.Scope == "project" {
		path = filepath.Join(c.Workdir, ".mcp.json")
	}
	if !wrap {
		return c.Ledger.Remove(ledger.Server, path, f.Name)
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

func (c *CLI) mcpFindings() ([]mcpconfig.Finding, []error) {
	if c.Home == "" {
		return nil, nil
	}
	servers, errs := mcpconfig.Load(c.Home, c.Workdir)
	refs := mcpconfig.References(doctor.DefaultPaths(c.Home, c.Workdir))
	return mcpconfig.Check(servers, refs), errs
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
