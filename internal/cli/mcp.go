package cli

import (
	"fmt"
	"strings"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// mcp shows each MCP server that would receive a cap:// reference, with the
// definition that runs it through keyward. It never edits a config: the tools
// own those files and may rewrite them while running.
func (c *CLI) mcp(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(c.Stderr, "usage: keyward mcp")
		return exitUsage
	}
	findings, errs := c.mcpFindings()
	for _, err := range errs {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not read an MCP config, so it was not checked: %v", err)))
	}
	if len(findings) == 0 {
		fmt.Fprintln(c.Stdout, "No MCP server needs a change.")
		return exitOK
	}
	fmt.Fprintf(c.Stdout, "%d MCP server(s) would receive cap:// references instead of values.\n"+
		"Run each through keyward, so only that server gets its secrets:\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(c.Stdout, "\n%s\n  uses %s (%s, %s)\n\n%s\n\n  %s\n",
			c.out(bold, f.Name), strings.Join(f.Vars, ", "), f.Client, c.tilde(f.Config),
			indent(f.Suggestion, "    "), c.tilde(f.Note))
	}
	fmt.Fprint(c.Stdout, "\nThen restart the tool. If mcp-remote reports a certificate error behind a\n"+
		"corporate proxy, add NODE_EXTRA_CA_CERTS to that server's env, pointing at your\n"+
		"trusted certificates.\n")
	return exitFailure
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
