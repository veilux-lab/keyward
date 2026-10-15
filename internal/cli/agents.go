package cli

import (
	"fmt"
	"path/filepath"

	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/migrate"
)

// agents writes the instructions for AI agents and says how to point each
// installed agent at them, for setups migrated before the file existed.
func (c *CLI) agents(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward agents")
		return exitUsage
	}
	if c.Home == "" {
		return c.fail("keyward agents: home directory unknown")
	}
	if err := agents.Default(c.Home).WriteRecorded(c.Ledger); err != nil {
		return c.fail("keyward agents: %v", err)
	}
	fmt.Fprintf(c.Stdout, "%s tells AI agents to run commands that need credentials through keyward.\n", agents.Display)
	if !c.printUnlinked() {
		fmt.Fprintln(c.Stdout, "Every installed agent already reads it.")
	}
	return exitOK
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
		c.printUnlinked()
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
