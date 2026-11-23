package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/resolve"
	"github.com/veilux-lab/keyward/internal/shell"
	"github.com/veilux-lab/keyward/internal/vault"
)

// programPath resolves a command name to the absolute path PATH finds, without
// following symlinks, which is how bindings are matched. A fake gh earlier on
// PATH therefore does not match the real one, and an upgrade that moves the real
// one inside Homebrew's Cellar does not break the binding.
func programPath(name string) (string, error) {
	found, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return filepath.Abs(found)
}

// bindingResolveKeys decides which referenced variables keyward run may resolve,
// given where the command would send their values.
//
// It returns the variables to resolve, or a refusal message when a secret the
// caller named with --only may not reach this command. A bound secret the
// command is not allowed is left unresolved when --only was not given, so an
// unrelated command keeps working; refused when it was, since the caller asked
// for it here. keys is only (every reference when nil) when nothing is bound, so
// a setup without bindings behaves exactly as before.
func (c *CLI) bindingResolveKeys(args, env, only []string) (keys []string, refusal string, err error) {
	candidates := resolve.Variables(env, only)
	if len(candidates) == 0 || c.Binder == nil {
		return only, "", nil
	}

	type bound struct {
		variable string
		secret   string
		bindings []vault.Binding
	}
	var boundVars []bound
	for _, v := range candidates {
		secret, ok := referencedSecret(env, v)
		if !ok {
			continue // a malformed reference; resolve reports it
		}
		// Read through the binder, not the activity-wrapped store, so a check of
		// where a secret may go is not logged as if the user listed secrets.
		bs, err := c.Binder.GetBindings(secret)
		if errors.Is(err, vault.ErrNotFound) {
			continue // resolve reports a reference with nothing behind it
		}
		if err != nil {
			return nil, "", err
		}
		if len(bs) > 0 {
			boundVars = append(boundVars, bound{v, secret, bs})
		}
	}
	if len(boundVars) == 0 {
		return only, "", nil
	}

	targets, err := c.targetPrograms(args)
	if err != nil {
		// A bound secret would enter a script running a command keyward cannot
		// name, so where its value goes cannot be checked.
		return nil, fmt.Sprintf("cannot check where a bound secret's value would go: %v\n  %s", err, shell.Hint(err)), nil
	}

	var exclude []string
	for _, b := range boundVars {
		if bindingAllows(b.bindings, targets) {
			continue
		}
		if only != nil {
			return nil, refuseBinding(b.variable, b.secret, b.bindings, targets), nil
		}
		exclude = append(exclude, b.variable)
	}
	if only != nil || len(exclude) == 0 {
		return only, "", nil
	}
	keys = slices.DeleteFunc(resolve.Variables(env, nil), func(v string) bool { return slices.Contains(exclude, v) })
	return keys, "", nil
}

// targetPrograms is the set of programs the command would run, as absolute
// paths. For a shell's script it is every external command the script runs; a
// command keyward cannot name is an error. For anything else it is the one
// program keyward run executes.
func (c *CLI) targetPrograms(args []string) ([]string, error) {
	if name, script, ok := shell.Command(args); ok {
		names, err := shell.Programs(name, script)
		if err != nil {
			return nil, err
		}
		paths := make([]string, 0, len(names))
		for _, n := range names {
			// A program not found on PATH cannot match any binding; keep the name
			// so it fails the check rather than passing silently.
			if p, err := programPath(n); err == nil {
				paths = append(paths, p)
			} else {
				paths = append(paths, n)
			}
		}
		return paths, nil
	}
	p, err := programPath(args[0])
	if err != nil {
		return nil, err
	}
	return []string{p}, nil
}

// bindingAllows reports whether a secret with these bindings may reach every one
// of targets. An unknown binding kind allows nothing, so it fails closed.
func bindingAllows(bindings []vault.Binding, targets []string) bool {
	allowed := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		if !b.Known() {
			return false
		}
		if b.Kind == vault.BindingProgram {
			allowed[b.Program] = true
		}
	}
	for _, t := range targets {
		if !allowed[t] {
			return false
		}
	}
	return true
}

// referencedSecret returns the secret name that env sets key to, if key holds a
// well-formed reference. The last entry wins, as it does for the command keyward
// run executes, so the binding checked is the one on the value that reaches it.
func referencedSecret(env []string, key string) (string, bool) {
	name, found := "", false
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			if h, err := handle.Parse(v); err == nil {
				name, found = h.Name, true
			} else {
				found = false
			}
		}
	}
	return name, found
}

// refuseBinding says why a bound secret may not reach this command, naming the
// secret, where it may go, and the program that runs here.
func refuseBinding(variable, secret string, bindings []vault.Binding, targets []string) string {
	var programs []string
	for _, b := range bindings {
		if b.Kind == vault.BindingProgram {
			programs = append(programs, b.Program)
		}
	}
	var blocked []string
	for _, t := range targets {
		if !slices.Contains(programs, t) {
			blocked = append(blocked, t)
		}
	}
	// No blocked program but still not allowed means a binding kind this keyward
	// does not understand, which allows nothing. (Phase 1 writes none of these.)
	if len(blocked) == 0 {
		return fmt.Sprintf("keyward run: %s is bound to %s in a way this keyward does not understand, so it may go nowhere.\n"+
			"  Update keyward, or remove the binding in a terminal: keyward unbind %s --all", variable, secret, secret)
	}
	where := "nothing"
	if len(programs) > 0 {
		where = "only " + strings.Join(programs, ", ")
	}
	return fmt.Sprintf("keyward run: %s is bound to %s, which may go to %s, but this command runs %s.\n"+
		"  To allow it, bind the secret to that program in a terminal: keyward bind %s --program %s\n"+
		"  An AI agent must not run keyward bind; ask the user to.",
		variable, secret, where, strings.Join(blocked, ", "), secret, strings.Join(blocked, " --program "))
}
