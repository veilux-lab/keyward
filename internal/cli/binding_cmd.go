package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
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
// terminal and a typed "yes", so an agent or a pipe cannot widen or add a
// restriction unseen.
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
	name, err := handle.Normalize(names[0])
	if err != nil {
		return c.fail("keyward bind: %v", err)
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
	// The secret must exist before anyone confirms binding it.
	if _, err := c.Binder.GetBindings(name); err != nil {
		return c.fail("keyward bind: %v", err)
	}
	if code := c.confirmBindingChange("bind", name); code != exitOK {
		return code
	}
	var bound []string
	for _, b := range bindings {
		if err := c.Binder.Bind(name, b); err != nil {
			return c.fail("keyward bind: %v", err)
		}
		bound = append(bound, b.Program)
	}
	fmt.Fprintf(c.Stdout, "%s may now be given only to: %s\n", name, strings.Join(bound, ", "))
	return exitOK
}

// unbind removes bindings. --all removes every one, leaving the secret
// unrestricted; otherwise it removes the named programs. It needs a terminal
// and a "yes", since removing a binding widens where a secret may go.
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
	if len(names) != 1 || (*all == (len(programs) > 0)) {
		fmt.Fprint(c.Stderr, "usage: keyward unbind <name> (--program <program> ... | --all)\n")
		return exitUsage
	}
	if c.Binder == nil {
		return c.fail("keyward unbind: unavailable without the keyward daemon")
	}
	if c.refuseNonTerminal("unbind") {
		return exitUsage
	}
	name, err := handle.Normalize(names[0])
	if err != nil {
		return c.fail("keyward unbind: %v", err)
	}
	current, err := c.Binder.GetBindings(name)
	if err != nil {
		return c.fail("keyward unbind: %v", err)
	}
	var remove []vault.Binding
	if *all {
		remove = current
	} else {
		for _, p := range programs {
			remove = append(remove, vault.Binding{Kind: vault.BindingProgram, Program: unbindPath(p)})
		}
	}
	if len(remove) == 0 {
		return c.cancel(fmt.Sprintf("keyward unbind: %s has no bindings to remove.", name))
	}
	if code := c.confirmBindingChange("unbind", name); code != exitOK {
		return code
	}
	for _, b := range remove {
		if err := c.Binder.Unbind(name, b); err != nil {
			return c.fail("keyward unbind: %v", err)
		}
	}
	fmt.Fprintf(c.Stdout, "Unbound %s.\n", name)
	return exitOK
}

// unbindPath matches how bind stored a program: an absolute path is taken as
// written, so a binding to a program since removed from PATH can still be
// removed; a bare name is resolved as bind resolved it.
func unbindPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if abs, err := programPath(p); err == nil {
		return abs
	}
	return p
}

// refuseNonTerminal refuses a binding change from an agent or a pipe, which must
// not change where a secret may go; a change needs a terminal, as copy does.
func (c *CLI) refuseNonTerminal(verb string) bool {
	if c.Interactive {
		return false
	}
	c.refused = true
	fmt.Fprintln(c.Stderr, c.errs(red, fmt.Sprintf("keyward %s: run it yourself in a terminal, not through an AI agent or a pipe. An AI agent must ask you to run it.", verb)))
	return true
}

// confirmBindingChange reads a typed "yes". Callers have already checked the
// secret exists, so no one confirms a name that is not there.
func (c *CLI) confirmBindingChange(verb, name string) int {
	action := map[string]string{"bind": "Change where", "unbind": "Remove the restriction on where"}[verb]
	if _, err := fmt.Fprintf(c.Stderr, "\n%s %s may go?\n  %s\n\n  Enter a value: ",
		action, name, c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord))); err != nil {
		return exitFailure
	}
	ok, err := c.readConfirmation()
	if err != nil {
		return c.fail("keyward %s: could not read confirmation", verb)
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
			switch {
			case b.Kind == vault.BindingProgram:
				fmt.Fprintf(c.Stdout, "    program  %s\n", b.Program)
			default:
				fmt.Fprintf(c.Stdout, "    %s  (this keyward does not understand this binding)\n", b.Kind)
			}
		}
	}
	if !any {
		fmt.Fprintln(c.Stdout, "No secrets are bound. keyward bind <name> --program <program> limits where one may go.")
	}
	return exitOK
}
