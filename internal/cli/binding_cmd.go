package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/vault"
)

// programList collects repeated --program values.
type programList []string

func (p *programList) String() string { return strings.Join(*p, ", ") }
func (p *programList) Set(v string) error {
	*p = append(*p, v)
	return nil
}

// bind limits a secret to the programs it may be given to. Like copy it needs a
// terminal and a typed "yes", so an agent or a pipe cannot change where a secret
// may go unseen.
func (c *CLI) bind(args []string) int {
	fs := flag.NewFlagSet("bind", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	var programs programList
	fs.Var(&programs, "program", "a program the secret may be given to (repeatable)")
	names, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(names) != 1 || len(programs) == 0 {
		fmt.Fprint(c.Stderr, "usage: keyward bind <name> --program <program> [--program ...]\n")
		return exitUsage
	}
	if c.Binder == nil {
		return c.fail("keyward bind: unavailable without the keyward daemon")
	}
	if c.refuseNonTerminal("bind") {
		return exitUsage
	}
	name, code := c.storedSecret("bind", names[0])
	if code != exitOK {
		return code
	}
	// Resolve the programs before asking, so the prompt shows the exact paths
	// that will be stored, and a typo fails before anyone says yes.
	var bindings []vault.Binding
	for _, p := range programs {
		abs, err := programPath(p)
		if err != nil {
			return c.fail("keyward bind: cannot find %s on your PATH: %v", p, err)
		}
		bindings = append(bindings, vault.Binding{Kind: vault.BindingProgram, Program: abs})
	}
	current, err := c.bindingsOf(name)
	if err != nil {
		return c.fail("keyward bind: %v", err)
	}
	after := append(slices.Clone(current), bindings...)
	c.warnStoppedServers(name, current, after)
	var lines []string
	for _, p := range programNames(after) {
		if slices.Contains(programNames(current), p) {
			p += " (already bound)"
		}
		lines = append(lines, p)
	}
	if code := c.confirmBindingChange("bind", fmt.Sprintf("Give %s only to these programs, started directly?", name), slices.Compact(lines)); code != exitOK {
		return code
	}
	for _, b := range bindings {
		if err := c.Binder.Bind(name, b); err != nil {
			return c.fail("keyward bind: %v", err)
		}
	}
	// The whole list, not just what this call added, which a secret already bound
	// would understate.
	if now, err := c.bindingsOf(name); err == nil {
		fmt.Fprintf(c.Stdout, "%s may now be given only to: %s\n", name, strings.Join(programNames(now), ", "))
	} else {
		fmt.Fprintf(c.Stdout, "Bound. keyward bindings lists where %s may go.\n", name)
	}
	return exitOK
}

// unbind removes bindings: --all removes every one, leaving the secret free to
// go to any program; --program removes those named, which narrows where it may
// go while others are left. Either needs a terminal and a "yes".
func (c *CLI) unbind(args []string) int {
	fs := flag.NewFlagSet("unbind", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	var programs programList
	all := fs.Bool("all", false, "remove every binding")
	fs.Var(&programs, "program", "a program binding to remove (repeatable)")
	names, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(names) != 1 || *all == (len(programs) > 0) {
		fmt.Fprint(c.Stderr, "usage: keyward unbind <name> (--program <program> ... | --all)\n")
		return exitUsage
	}
	if c.Binder == nil {
		return c.fail("keyward unbind: unavailable without the keyward daemon")
	}
	if c.refuseNonTerminal("unbind") {
		return exitUsage
	}
	name, code := c.storedSecret("unbind", names[0])
	if code != exitOK {
		return code
	}
	current, err := c.bindingsOf(name)
	if err != nil {
		return c.fail("keyward unbind: %v", err)
	}
	if len(current) == 0 {
		return c.cancel(fmt.Sprintf("keyward unbind: %s is not bound, so it may already go to any program.", name))
	}
	remove := current
	if !*all {
		remove = nil
		for _, p := range programs {
			b := vault.Binding{Kind: vault.BindingProgram, Program: unbindPath(p)}
			if !slices.Contains(current, b) {
				return c.fail("keyward unbind: %s is not bound to %s; keyward bindings lists where it may go", name, b.Program)
			}
			remove = append(remove, b)
		}
	}
	left := slices.DeleteFunc(slices.Clone(current), func(b vault.Binding) bool { return slices.Contains(remove, b) })
	question := fmt.Sprintf("Let %s go to any program again?", name)
	lines := []string{"It is bound to: " + strings.Join(programNames(current), ", ")}
	if len(left) > 0 {
		// Narrowing can stop an MCP server that runs a program being removed.
		c.warnStoppedServers(name, current, left)
		question = fmt.Sprintf("Stop giving %s to these programs?", name)
		lines = append(programNames(remove), "It will still go only to: "+strings.Join(programNames(left), ", "))
	}
	if code := c.confirmBindingChange("unbind", question, lines); code != exitOK {
		return code
	}
	for _, b := range remove {
		if err := c.Binder.Unbind(name, b); err != nil {
			return c.fail("keyward unbind: %v", err)
		}
	}
	// What is left, which a secret with other bindings still has.
	now, err := c.bindingsOf(name)
	switch {
	case err != nil:
		fmt.Fprintf(c.Stdout, "Removed. keyward bindings lists what %s has left.\n", name)
	case len(now) == 0:
		fmt.Fprintf(c.Stdout, "%s is no longer bound; it may be given to any program again.\n", name)
	default:
		fmt.Fprintf(c.Stdout, "%s may now be given only to: %s\n", name, strings.Join(programNames(now), ", "))
	}
	return exitOK
}

// bindingsOf returns name's bindings, none if it may go to any program.
func (c *CLI) bindingsOf(name string) ([]vault.Binding, error) {
	all, err := c.Binder.Bindings()
	return all[name], err
}

// programNames lists the program paths of bindings, for a message.
func programNames(bindings []vault.Binding) []string {
	var out []string
	for _, b := range bindings {
		if b.Kind == vault.BindingProgram {
			out = append(out, b.Program)
		}
	}
	return out
}

// unbindPath matches how bind stored a program: an absolute path is taken as
// written, so a binding to a program since removed from PATH can still be
// removed; a bare name is resolved as bind resolved it.
func unbindPath(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if abs, err := programPath(p); err == nil {
		return abs
	}
	return p
}

// warnStoppedServers names the MCP servers that get name through keyward run
// under the bindings before, which none is, but not under after, as keyward run
// gives a bound secret only to a bound program it starts directly, before anyone
// says yes to stopping them.
func (c *CLI) warnStoppedServers(name string, before, after []vault.Binding) {
	if c.Home == "" {
		return
	}
	servers, errs := c.loadAll()
	c.reportUnreadable(errs)
	refs := mcpconfig.References(doctor.DefaultPaths(c.Home, c.Workdir))
	var stopped []string
	for _, w := range mcpconfig.WrappedServers(servers, refs) {
		if !slices.Contains(w.Secrets, name) || len(w.Command) == 0 || mcpconfig.Gone(w.Project) {
			continue
		}
		if (len(before) == 0 || reaches(before, w.Command)) && !reaches(after, w.Command) {
			stopped = append(stopped, fmt.Sprintf("  %s (%s, %s)", w.Name, w.Client, c.tilde(w.Config)))
		}
	}
	if len(stopped) > 0 {
		fmt.Fprintln(c.Stderr, c.errs(yellow, "These MCP servers would stop working, as keyward run would no longer give them "+name+":\n"+
			strings.Join(stopped, "\n")+"\n  Give each a secret of its own first."))
	}
}

// refuseNonTerminal refuses a binding change from an agent or a pipe, which must
// not change where a secret may go; a change needs a terminal, as copy does.
func (c *CLI) refuseNonTerminal(verb string) bool {
	if c.Interactive {
		return false
	}
	c.refused = true
	fmt.Fprintln(c.Stderr, c.errs(red, fmt.Sprintf("keyward %s: run it yourself in a terminal, not through an AI agent or a pipe, so only you can change where a secret may go.", verb)))
	return true
}

// confirmBindingChange asks question, with lines saying what changes, and reads
// a typed "yes". Callers have already checked what it names exists, so no one
// confirms a change to nothing.
func (c *CLI) confirmBindingChange(command, question string, lines []string) int {
	if _, err := fmt.Fprintf(c.Stderr, "\n%s\n  %s\n  %s\n\n  Enter a value: ",
		question, strings.Join(lines, "\n  "), c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord))); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward %s: could not read confirmation", command)
	}
	if !ok {
		return c.cancel("Aborted. Bindings were not changed.")
	}
	return exitOK
}

// bindings lists each bound secret and where it may go, never a value, and needs
// no terminal: it reveals nothing an agent should not see.
func (c *CLI) bindings(args []string) int {
	if len(args) != 0 {
		fmt.Fprint(c.Stderr, "usage: keyward bindings\n")
		return exitUsage
	}
	entries, err := c.Store.Entries()
	if err != nil {
		return c.fail("keyward bindings: %v", err)
	}
	var any bool
	for _, e := range entries {
		if len(e.Bindings) == 0 {
			continue
		}
		any = true
		fmt.Fprintln(c.Stdout, e.Name)
		for _, b := range e.Bindings {
			if b.Known() {
				fmt.Fprintf(c.Stdout, "    program  %s\n", b.Program)
			} else {
				fmt.Fprintf(c.Stdout, "    %s  (this keyward does not understand this binding)\n", b.Kind)
			}
		}
	}
	if !any {
		fmt.Fprintln(c.Stdout, "No secrets are bound. keyward bind <name> --program <program> limits where one may go.")
	}
	return exitOK
}
