// Package cli implements the keyward commands.
//
// The logic lives here rather than in main so it can be tested without touching
// the real Keychain or replacing the process: the store, the output streams, the
// environment, and exec itself are all injected. cmd/keyward only wires the real
// implementations in.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/nwokolo24/keyward/internal/handle"
	"github.com/nwokolo24/keyward/internal/migrate"
	"github.com/nwokolo24/keyward/internal/resolve"
	"github.com/nwokolo24/keyward/internal/vault"
)

// Version is the build version, overridable at link time.
var Version = "dev"

// Exit codes. Distinguishing usage errors from runtime failures lets a script,
// or an agent, tell "I typed it wrong" from "it did not work".
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// CLI holds everything the commands need. Every field is injected so the whole
// surface is testable.
type CLI struct {
	Store  vault.Store
	Stdout io.Writer
	Stderr io.Writer

	// Environ supplies the environment to resolve, normally os.Environ.
	Environ func() []string

	// ReadSecret reads a secret value, normally from stdin with terminal echo
	// disabled. A function so no test needs a terminal.
	ReadSecret func() ([]byte, error)

	// Exec replaces the current process, normally syscall.Exec. Injected because
	// the real thing cannot return, and therefore cannot be tested.
	Exec func(path string, argv []string, env []string) error
}

const usage = `usage: keyward <command> [arguments]

Secrets live in the macOS Keychain. Config files hold cap://<name> references
instead of values, so an agent reading them finds nothing worth having.

commands:
  add [-force] <name>   store a secret read from stdin
  ls                    list stored secret names
  rm <name>             remove a secret
  run [--] <cmd>...     resolve cap:// references and run a command
  migrate <file>        describe moving a file's secrets into the Keychain
  migrate -apply <file> actually move them
  version               print the version
  help                  print this message

examples:
  pbpaste | keyward add splunk-mcp-token
  keyward run -- npm test
  keyward migrate ~/.zshrc          # dry run: describes, changes nothing
  keyward migrate -apply ~/.zshrc   # make the changes
`

// Run dispatches a command and returns a process exit code.
func (c *CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, usage)
		return exitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(c.Stdout, usage)
		return exitOK
	case "version":
		fmt.Fprintln(c.Stdout, Version)
		return exitOK
	case "add":
		return c.add(args[1:])
	case "ls":
		return c.list()
	case "rm":
		return c.remove(args[1:])
	case "run":
		return c.run(args[1:])
	case "migrate":
		return c.migrate(args[1:])
	default:
		fmt.Fprintf(c.Stderr, "keyward: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

// add stores a secret read from stdin.
//
// The value is never taken from an argument. A secret in argv is visible to `ps`
// for every user on the machine and lands in shell history, which would make the
// tool a worse place to put a credential than the file it was moved out of.
func (c *CLI) add(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	force := fs.Bool("force", false, "replace the value if the name already exists")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprint(c.Stderr, "usage: keyward add [-force] <name>\n")
		return exitUsage
	}
	name := fs.Arg(0)

	// Validate before reading, so a typo is caught without the user first typing
	// or piping a credential.
	if _, err := handle.Normalize(name); err != nil {
		return c.fail("keyward add: %v", err)
	}

	value, err := c.ReadSecret()
	if err != nil {
		return c.fail("keyward add: reading the value: %v", err)
	}
	secret := vault.NewSecret(value)
	for i := range value {
		value[i] = 0
	}
	defer secret.Destroy()

	if *force {
		// Replace requires the name to exist, so fall back to Put. -force means
		// "do not stop me", not "the name must already be there".
		if err := c.Store.Replace(name, secret); err != nil {
			if !errors.Is(err, vault.ErrNotFound) {
				return c.fail("keyward add: %v", err)
			}
			if err := c.Store.Put(name, secret); err != nil {
				return c.fail("keyward add: %v", err)
			}
		}
		return exitOK
	}

	if err := c.Store.Put(name, secret); err != nil {
		if errors.Is(err, vault.ErrExists) {
			return c.fail("keyward add: %q already exists; pass -force to replace it", name)
		}
		return c.fail("keyward add: %v", err)
	}
	return exitOK
}

// list prints stored names, one per line and nothing else, so the output pipes
// into other commands without needing to be filtered.
func (c *CLI) list() int {
	names, err := c.Store.List()
	if err != nil {
		return c.fail("keyward ls: %v", err)
	}
	for _, n := range names {
		fmt.Fprintln(c.Stdout, n)
	}
	return exitOK
}

func (c *CLI) remove(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(c.Stderr, "usage: keyward rm <name>\n")
		return exitUsage
	}
	if err := c.Store.Delete(args[0]); err != nil {
		return c.fail("keyward rm: %v", err)
	}
	return exitOK
}

// run resolves every cap:// reference in the environment and replaces this
// process with the requested command.
//
// Resolution happens before anything is executed. If any reference fails, nothing
// runs — a command started with a literal cap:// value where a credential belongs
// fails in a way that looks like a bad token rather than a missing one.
func (c *CLI) run(args []string) int {
	// A leading -- is conventional and supported, but not required.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, "usage: keyward run [--] <command> [arguments]\n")
		return exitUsage
	}

	result, err := resolve.New(c.Store).Env(c.Environ())
	if err != nil {
		return c.failResolve(err)
	}

	// Look the command up before exec so a typo is a clear message rather than an
	// opaque failure from the exec call.
	path, err := exec.LookPath(args[0])
	if err != nil {
		return c.fail("keyward run: %v", err)
	}

	if err := c.Exec(path, args, result.Env); err != nil {
		return c.fail("keyward run: executing %s: %v", args[0], err)
	}
	// Reached only when Exec is a test double; the real one does not return.
	return exitOK
}

// migrate moves the secrets in a file into the vault and leaves references.
//
// A dry run is the default and -apply is required to change anything. A tool that
// rewrites a shell config on a bare command is a tool people run once, and the
// diff is the whole point: the detector proposes, the human decides.
func (c *CLI) migrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	apply := fs.Bool("apply", false, "make the changes, rather than only describing them")
	// Redundant with the default, and worth having: -dry-run is a strong enough
	// convention that its absence leaves people unsure whether the bare command is
	// safe to run.
	dryRun := fs.Bool("dry-run", false, "describe the changes without making them (the default)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dryRun && *apply {
		// Guessing which was meant is how a script intended to preview ends up
		// rewriting a shell config.
		fmt.Fprint(c.Stderr, "keyward migrate: -dry-run and -apply contradict each other; pass one or neither\n")
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprint(c.Stderr, "usage: keyward migrate [-apply | -dry-run] <file>\n")
		return exitUsage
	}

	plan, err := migrate.Read(fs.Arg(0))
	if err != nil {
		return c.fail("keyward migrate: %v", err)
	}

	if plan.Empty() {
		fmt.Fprintf(c.Stdout, "%s: nothing to move\n", plan.Path)
		return exitOK
	}

	// The diff withholds values; see migrate.Plan.Diff.
	fmt.Fprint(c.Stdout, plan.Diff())

	if !*apply {
		fmt.Fprintf(c.Stdout, "\nThis was a dry run. Re-run with -apply to make these changes.\n")
		return exitOK
	}

	applied, err := plan.Apply(c.Store)
	if err != nil {
		return c.fail("keyward migrate: %v", err)
	}

	fmt.Fprintf(c.Stdout, "\nStored %d secret(s): %s\n", len(applied.Stored), strings.Join(applied.Stored, ", "))
	fmt.Fprintf(c.Stdout, "Original saved to %s\n", applied.BackupPath)
	fmt.Fprintf(c.Stdout, "\nRun commands that need these values through keyward, for example:\n  keyward run -- your-command\n")
	return exitOK
}

// failResolve renders resolution failures with a suggested fix.
//
// The resolve package deliberately does not know keyward's command names, so
// turning a cause into an actionable instruction belongs here. The hint matters:
// an error that names the next step is the difference between an agent recovering
// and an agent guessing.
func (c *CLI) failResolve(err error) int {
	var rerr *resolve.Error
	if !errors.As(err, &rerr) {
		// Defensive, and deliberately kept: resolve.Env only returns *resolve.Error
		// today, so this is unreachable and shows as uncovered. Without it, a future
		// error type added to resolve would print nothing at all here.
		return c.fail("keyward run: %v", err)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "keyward run: %d reference(s) could not be resolved:\n", len(rerr.Failures))
	for _, f := range rerr.Failures {
		fmt.Fprintf(&b, "  %s=%s\n    %v\n", f.Key, f.Ref, f.Err)
		if hint := fixHint(f); hint != "" {
			fmt.Fprintf(&b, "    %s\n", hint)
		}
	}
	fmt.Fprint(c.Stderr, b.String())
	return exitFailure
}

// fixHint suggests a next step for one failure, or "" when there is nothing
// useful to say beyond the cause.
func fixHint(f resolve.Failure) string {
	switch {
	case errors.Is(f.Err, vault.ErrNotFound):
		name := strings.TrimPrefix(f.Ref, handle.Prefix)
		return fmt.Sprintf("add it with: keyward add %s", name)
	case errors.Is(f.Err, vault.ErrDenied):
		return "unlock your keychain, or approve the access prompt, then try again"
	case errors.Is(f.Err, handle.ErrInvalidName),
		errors.Is(f.Err, handle.ErrEmptyName),
		errors.Is(f.Err, handle.ErrNameTooLong):
		return "fix the reference where it is written, then try again"
	default:
		return ""
	}
}

// fail writes a message to stderr and returns the failure exit code. Callers pass
// causes, never values.
func (c *CLI) fail(format string, args ...any) int {
	fmt.Fprintf(c.Stderr, format+"\n", args...)
	return exitFailure
}
