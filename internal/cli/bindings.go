package cli

import (
	"fmt"
	"os/exec"
	"path"
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

// reaches reports whether a secret with these bindings may go to the command
// argv starts: only to a bound program keyward run starts directly, never to a
// shell's script, which can pass a value on in ways keyward cannot follow, as a
// redirect to /dev/tcp does. A binding of a kind this keyward does not know
// allows nothing.
func reaches(bindings []vault.Binding, argv []string) bool {
	if _, _, script := shell.Command(argv); script {
		return false
	}
	program := argv[0]
	if p, err := programPath(program); err == nil {
		program = p
	}
	allowed := false
	for _, b := range bindings {
		if !b.Known() {
			return false
		}
		allowed = allowed || b.Program == program
	}
	return allowed
}

// bindingResolveKeys decides which referenced variables keyward run may resolve
// for args. A bound secret the command may not have is refused when --only names
// it, since the caller asked for it here, and otherwise left unresolved, so an
// unrelated command keeps working. With nothing bound it returns only, so a
// setup without bindings behaves as before.
func (c *CLI) bindingResolveKeys(args, env, only []string) (keys []string, refusal string, err error) {
	vars := resolve.Variables(env, only)
	if len(vars) == 0 || c.Binder == nil {
		return only, "", nil
	}
	// One request for all of them, through the binder rather than the activity-
	// wrapped store, so checking where secrets may go is not logged as a list.
	all, err := c.Binder.Bindings()
	if err != nil {
		return nil, "", err
	}
	var exclude []string
	for _, v := range vars {
		secret, ok := referencedSecret(env, v)
		if !ok || len(all[secret]) == 0 || reaches(all[secret], args) {
			continue // a malformed reference, which resolve reports, or one free to go
		}
		if only != nil {
			return nil, refuseBinding(v, secret, all[secret], args), nil
		}
		exclude = append(exclude, v)
	}
	if len(exclude) == 0 {
		return only, "", nil
	}
	return slices.DeleteFunc(resolve.Variables(env, nil), func(v string) bool { return slices.Contains(exclude, v) }), "", nil
}

// referencedSecret returns the secret name that env sets key to, if key holds a
// well-formed reference. The first entry wins: os.Environ, keyward's env source,
// keeps only the first of any duplicated key, and a child's getenv reads the
// first too, so the first is the value the program actually sees.
func referencedSecret(env []string, key string) (string, bool) {
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			h, err := handle.Parse(v)
			if err != nil {
				return "", false
			}
			return h.Name, true
		}
	}
	return "", false
}

// refuseBinding says why variable's secret may not go to the command argv
// starts, and how to run the program it is bound to instead.
func refuseBinding(variable, secret string, bindings []vault.Binding, argv []string) string {
	var programs []string
	for _, b := range bindings {
		if !b.Known() {
			return fmt.Sprintf("keyward run: %s holds %s, which is bound in a way this keyward does not understand, so it goes to no program.\n"+
				"  Update keyward, or remove the binding yourself in a terminal: keyward unbind %s --all", variable, secret, secret)
		}
		programs = append(programs, b.Program)
	}
	where := strings.Join(programs, ", ")
	if _, _, script := shell.Command(argv); script {
		message := fmt.Sprintf("keyward run: %s holds %s, which goes only to %s, never to a script.\n"+
			"  Start %s directly, one call per keyward run, with loops, pipes and redirects outside it.",
			variable, secret, where, path.Base(programs[0]))
		if slices.ContainsFunc(programs, func(p string) bool { return path.Base(p) == "curl" }) {
			message += fmt.Sprintf("\n  curl 8.3 or later reads the value itself: curl --variable %%%s --expand-header 'Authorization: Bearer {{%s}}' URL", variable, variable)
		}
		return message
	}
	program := argv[0]
	if p, err := programPath(program); err == nil {
		program = p
	}
	return fmt.Sprintf("keyward run: %s holds %s, which goes only to %s, not to %s.\n"+
		"  Start %s directly. To let another program have it, bind that one yourself in a terminal: keyward bind %s --program PROGRAM",
		variable, secret, where, program, path.Base(programs[0]), secret)
}
