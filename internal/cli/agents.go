package cli

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/migrate"
)

// agents writes the instructions for AI agents and shows which agents read them;
// link and unlink add or remove the one line in each agent's instructions.
func (c *CLI) agents(args []string) int {
	if c.Home == "" {
		return c.fail("keyward agents: home directory unknown")
	}
	switch {
	case len(args) == 1 && args[0] == "link":
		return c.agentsLink()
	case len(args) == 1 && args[0] == "unlink":
		return c.agentsUnlink()
	case len(args) != 0:
		fmt.Fprintln(c.Stderr, "usage: keyward agents [link|unlink]")
		return exitUsage
	}
	if err := agents.Default(c.Home).WriteRecorded(c.Ledger); err != nil {
		return c.fail("keyward agents: %v", err)
	}
	fmt.Fprintf(c.Stdout, "%s tells AI agents to run commands that need credentials through keyward.\n", agents.Display)
	if !c.printUnlinked() {
		fmt.Fprintln(c.Stdout, "Every installed agent already reads it.")
		return exitOK
	}
	fmt.Fprintln(c.Stdout, "keyward agents link adds these lines for you.")
	return exitOK
}

func (c *CLI) agentsLink() int {
	if err := agents.Default(c.Home).WriteRecorded(c.Ledger); err != nil {
		return c.fail("keyward agents link: %v", err)
	}
	missing := agents.Unlinked(c.Home)
	if len(missing) == 0 {
		fmt.Fprintf(c.Stdout, "Every installed agent already reads %s.\n", agents.Display)
		return exitOK
	}
	if !c.Interactive {
		c.printUnlinked()
		fmt.Fprintln(c.Stdout, "Run keyward agents link in a terminal to have keyward add them.")
		return exitFailure
	}
	fmt.Fprintf(c.Stdout, "Point these agents at %s, one line each:\n", agents.Display)
	for _, a := range missing {
		fmt.Fprintf(c.Stdout, "  %s  + %s\n", c.tilde(a.Config), a.Line)
	}
	if ok, err := c.ask("Add these lines?"); err != nil || !ok {
		return c.cancel("Nothing was changed.")
	}
	failed := false
	for _, a := range missing {
		created, err := a.Link()
		if err == nil {
			err = c.Ledger.Add(ledger.Record{Kind: ledger.Link, Path: a.Config, Text: a.Line, Created: created})
		}
		if err != nil {
			fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("  %s: %v", c.tilde(a.Config), err)))
			failed = true
			continue
		}
		fmt.Fprintln(c.Stdout, c.out(green, "  ✓ "+a.Name))
	}
	if failed {
		return exitFailure
	}
	return exitOK
}

func (c *CLI) agentsUnlink() int {
	records, err := c.Ledger.Records()
	if err != nil {
		return c.fail("keyward agents unlink: %v", err)
	}
	var mine []ledger.Record
	for _, r := range records {
		if r.Kind == ledger.Link {
			mine = append(mine, r)
		}
	}
	// Lines the user added by hand are theirs to remove.
	var theirs []string
	for _, config := range agents.Linked(c.Home) {
		if !slices.ContainsFunc(mine, func(r ledger.Record) bool { return r.Path == config }) {
			theirs = append(theirs, config)
		}
	}
	for _, config := range theirs {
		fmt.Fprintf(c.Stdout, "%s mentions keyward.md, but keyward did not add that line; remove it yourself.\n", c.tilde(config))
	}
	if len(mine) == 0 {
		if len(theirs) == 0 {
			fmt.Fprintln(c.Stdout, "No agent instructions point at keyward.")
			return exitOK
		}
		return exitFailure
	}
	fmt.Fprintln(c.Stdout, "Remove the line keyward added to each:")
	for _, r := range mine {
		fmt.Fprintf(c.Stdout, "  %s  - %s\n", c.tilde(r.Path), r.Text)
	}
	if !c.Interactive {
		fmt.Fprintln(c.Stdout, "Run keyward agents unlink in a terminal to have keyward remove them.")
		return exitFailure
	}
	if ok, err := c.ask("Remove these lines?"); err != nil || !ok {
		return c.cancel("Nothing was changed.")
	}
	failed := false
	for _, r := range mine {
		err := agents.Unlink(r.Path, r.Text, r.Created)
		if err == nil {
			err = c.Ledger.Remove(ledger.Link, r.Path, "")
		}
		if err != nil {
			fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("  %s: %v", c.tilde(r.Path), err)))
			failed = true
		}
	}
	if failed || len(theirs) > 0 {
		return exitFailure
	}
	fmt.Fprintln(c.Stdout, c.out(green, "✓ Removed."))
	return exitOK
}

// ask puts a question on stderr and accepts only the exact confirmation word.
func (c *CLI) ask(question string) (bool, error) {
	if _, err := fmt.Fprint(c.Stderr, "\n"+question+" "+c.errs(bold, fmt.Sprintf("Type %q:", confirmWord))+" "); err != nil {
		return false, err
	}
	return c.readConfirmation()
}

// recordRewrite notes a migrated file and its quoting. The file is already
// rewritten, so a failure only warns: discovery still finds it from the vault.
func (c *CLI) recordRewrite(plan *migrate.Plan) {
	if c.Ledger.Path == "" {
		return
	}
	quotes := map[string]string{}
	for _, change := range plan.Changes {
		quotes[change.Name] = change.Quote()
	}
	path, err := filepath.Abs(plan.Path)
	if err == nil {
		err = c.Ledger.Add(ledger.Record{Kind: ledger.Rewrite, Path: path, Quotes: quotes})
	}
	if err != nil {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("keyward migrate: could not record the change for uninstall: %v", err)))
	}
}

// agentNextSteps follows a migration: installation wrote the file, so this only
// says how to point agents at it.
func (c *CLI) agentNextSteps() {
	if c.Home == "" {
		return
	}
	switch st, err := agents.Default(c.Home).Status(); {
	case err != nil || st == agents.Foreign:
	case st == agents.Missing:
		fmt.Fprintf(c.Stdout, "\nTo tell AI agents how to use these references: keyward agents\n")
	default:
		if c.printUnlinked() {
			fmt.Fprintln(c.Stdout, "keyward agents link adds these lines for you.")
		}
	}
}

// printUnlinked lists the line to add for each agent not yet pointed at the file.
func (c *CLI) printUnlinked() bool {
	missing := agents.Unlinked(c.Home)
	if len(missing) == 0 {
		return false
	}
	fmt.Fprintf(c.Stdout, "\nPoint your AI agents at %s:\n", agents.Display)
	for _, a := range missing {
		fmt.Fprintf(c.Stdout, "  %-12s %s\n", a.Name+":", a.Command)
	}
	return true
}

// unlinkedAgents is doctor's count of agents that would miss the instructions.
func (c *CLI) unlinkedAgents() int {
	if c.Home == "" {
		return 0
	}
	if st, err := agents.Default(c.Home).Status(); err != nil || st == agents.Missing {
		return 0
	}
	return len(agents.Unlinked(c.Home))
}
