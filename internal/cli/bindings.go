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
// redirect to /dev/tcp does. A binding this keyward does not understand allows
// nothing.
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

// loaders names the DYLD_ variables in env, which make a program load other code
// that would get a bound secret with it.
func loaders(env []string) []string {
	var names []string
	for _, e := range env {
		if name, _, ok := strings.Cut(e, "="); ok && strings.HasPrefix(name, "DYLD_") {
			names = append(names, name)
		}
	}
	return names
}

// bindingResolveKeys decides which referenced variables keyward run may resolve
// for args. A bound secret the command may not have is refused when --only names
// it, since the caller asked for it here, and otherwise left unresolved, with a
// note saying why, so an unrelated command keeps working. With nothing bound it
// returns only, so a setup without bindings behaves as before.
func (c *CLI) bindingResolveKeys(args, env, only []string) (keys, notes []string, refusal string, err error) {
	vars := resolve.Variables(env, only)
	if len(vars) == 0 || c.Binder == nil {
		return only, nil, "", nil
	}
	// One request for all of them, through the binder rather than the activity-
	// wrapped store, so checking where secrets may go is not logged as a list.
	all, err := c.Binder.Bindings()
	if err != nil {
		return nil, nil, "", err
	}
	var exclude []string
	for _, v := range vars {
		secret, ok := referencedSecret(env, v)
		if !ok || len(all[secret]) == 0 {
			continue // a malformed reference, which resolve reports, or one free to go
		}
		reason, fix := withheld(v, secret, all[secret], args, env)
		if reason == "" {
			continue
		}
		if only != nil {
			return nil, nil, fmt.Sprintf("keyward run: %s holds %s, which %s.\n  %s", v, secret, reason, fix), nil
		}
		exclude = append(exclude, v)
		notes = append(notes, fmt.Sprintf("keyward run: %s stays %s%s, which %s.", v, handle.Prefix, secret, reason))
	}
	if len(exclude) == 0 {
		return only, nil, "", nil
	}
	return slices.DeleteFunc(resolve.Variables(env, nil), func(v string) bool { return slices.Contains(exclude, v) }), notes, "", nil
}

// withheld says why variable's secret, bound as bindings say, may not go to the
// command argv starts with env, and what to do instead, or returns "" if it may.
func withheld(variable, secret string, bindings []vault.Binding, argv, env []string) (reason, fix string) {
	var programs []string
	for _, b := range bindings {
		if !b.Known() {
			return "is bound in a way this keyward does not understand, so it goes to no program", "Update keyward to use it."
		}
		programs = append(programs, b.Program)
	}
	where, first := strings.Join(programs, ", "), path.Base(programs[0])
	program := argv[0]
	if p, err := programPath(program); err == nil {
		program = p
	}
	if name, _, script := shell.Command(argv); script {
		if path.Base(program) != name && slices.Contains(programs, program) {
			// Started directly, as it should be, but its own words run a script.
			return "goes only to " + where + ", never to a script, and its words start a script", "Run " + path.Base(program) + " without a shell script among its words."
		}
		fix = fmt.Sprintf("Start %s directly, one call per keyward run, with loops, pipes and redirects outside it.", first)
		if slices.ContainsFunc(programs, func(p string) bool { return path.Base(p) == "curl" }) {
			fix += fmt.Sprintf("\n  curl 8.3 or later reads the value itself: curl --variable %%%s --expand-header 'Authorization: Bearer {{%s}}' URL", variable, variable)
		}
		return "goes only to " + where + ", never to a script", fix
	}
	if !reaches(bindings, argv) {
		return "goes only to " + where + ", not to " + program, fmt.Sprintf("Start %s directly; keyward bindings lists where each secret may go.", first)
	}
	if names := loaders(env); len(names) > 0 {
		set := strings.Join(names, ", ")
		return "goes only to " + where + ", and " + set + " would load other code into it", "Run it without " + set + "."
	}
	return "", ""
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
