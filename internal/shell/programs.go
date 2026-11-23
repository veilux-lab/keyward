package shell

import (
	"maps"
	"slices"

	"mvdan.cc/sh/v3/syntax"
)

// Programs returns the external programs that script, run as shell -c script,
// would execute, so keyward run can check each against a bound secret's
// program bindings. Launchers such as sudo and env, and nested shells, pass the
// environment through to the program after them and are transparent; the
// program that receives it is recorded.
//
// It fails closed: a command whose name is made as the script runs, code the
// shell reads as it runs such as eval's, or a script it cannot parse or follow
// to its end, is an error, which keyward run turns into a refusal. shell is sh,
// bash, dash or zsh, as Command returns.
func Programs(shell, script string) ([]string, error) {
	c := &checker{index: map[key]int{}, calling: map[*syntax.Stmt][]call{}, timed: map[*syntax.CallExpr]bool{},
		aliasing: map[string]bool{}, late: map[*syntax.Stmt]bool{}, parsed: map[parsing]*syntax.File{},
		resolved: map[string]taint{}, collecting: true, programs: map[string]bool{}}
	p := c.newProcess(shell, nil)
	c.script(p, script, 1, stream{})
	switch {
	case c.steps > maxSteps:
		c.cannotRead(p, script, unreadable{"the script would take too long to check", toSimplify})
	case c.text > maxText:
		c.cannotRead(p, script, unreadable{"the script's variables would hold too much text to check", toSimplify})
	case c.unsettled:
		c.cannotRead(p, script, unreadable{"a loop passes values along too many variables to check", toSimplify})
	case c.recursed:
		c.cannotRead(p, script, unreadable{"a function calls itself too deeply to check", toSimplify})
	}
	if c.err != nil {
		return nil, c.err
	}
	return slices.Sorted(maps.Keys(c.programs)), nil
}
