// Package cli implements the keyward commands.
//
// The logic lives here rather than in main so it can be tested without touching
// the real Keychain or replacing the process: the store, the output streams, the
// environment, and exec itself are all injected. cmd/keyward only wires the real
// implementations in.
package cli

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/exposure"
	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/mask"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/migrate"
	"github.com/veilux-lab/keyward/internal/resolve"
	"github.com/veilux-lab/keyward/internal/shell"
	"github.com/veilux-lab/keyward/internal/vault"
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

	// Stdin answers confirmation prompts. Secret values are read through
	// ReadSecret instead, so nothing reads both in one command.
	Stdin io.Reader

	// Environ supplies the environment to resolve, normally os.Environ.
	Environ func() []string

	// ReadSecret reads a secret value, normally from stdin with terminal echo
	// disabled. A function so no test needs a terminal.
	ReadSecret func() ([]byte, error)

	// Exec replaces the current process, normally syscall.Exec. Injected because
	// the real thing cannot return, and therefore cannot be tested.
	Exec func(path string, argv []string, env []string) error

	// RunMasked runs a command with these values hidden in its output, normally
	// mask.Run. run uses it when stdout or stderr is not a terminal and a value it
	// resolved is worth hiding, unless --no-mask; nil runs every command through
	// Exec.
	RunMasked func(path string, argv, env []string, secrets []mask.Secret) (mask.Exit, error)
	// Die ends keyward for the signal that ended a command RunMasked ran,
	// normally mask.Die.
	Die func(syscall.Signal)
	// TerminalOut and TerminalErr say whether stdout and stderr are terminals,
	// whose output run leaves as it is.
	TerminalOut, TerminalErr bool

	// Home and Workdir locate the files doctor reads by default. Fields rather than
	// calls to os.UserHomeDir and os.Getwd so a test can point them at a temp
	// directory instead of the developer's own configuration.
	Home    string
	Workdir string

	// Daemon serves the Keychain to the other commands until interrupted.
	// Injected because it binds a socket and owns the real Keychain.
	Daemon func() error

	// Backups holds migrate's encrypted copies of the originals.
	Backups backup.Dir

	// DataDirs are deleted by uninstall; empty for isolated instances.
	DataDirs []string
	// KeepDir, inside a data dir, holds the vault: kept unless uninstall purges.
	KeepDir string
	// Ledger records what keyward changed outside its data; empty Path, nothing.
	Ledger ledger.Ledger
	// LookPath and RunTool find and run other tools' CLIs, such as claude.
	LookPath func(string) (string, error)
	RunTool  func(dir string, argv ...string) ([]byte, error)
	// Self is keyward's stable path, written into configs keyward edits.
	Self string
	// Exposures asks the daemon which secrets are in a running program's command
	// line, so doctor never holds a value; nil skips that check.
	Exposures func() ([]exposure.Exposure, error)

	// inSetup quiets each step's closing advice; setup gives it once at the end.
	inSetup bool

	// in reads every confirmation of one run, so no answer is lost to a buffer.
	in    *bufio.Reader
	inSrc io.Reader
	// PurgeVault deletes the vault and its Keychain key, for uninstall --purge.
	PurgeVault func() error
	// RemovePackage deletes the installed program after its data; nil for development builds.
	RemovePackage func() (string, error)

	// Service manages the signed installation and login agent.
	Service func(action string) (string, error)

	// Recovery exports and restores the vault key; nil without a daemon.
	Recovery vault.KeyRecovery
	// RecoveryMarker records that a recovery code was shown, ending the reminders.
	RecoveryMarker string
	// Interactive is true when stdin and stdout are both terminals.
	Interactive bool

	// ColorOut and ColorErr enable ANSI colour on each stream; see ColorEnabled.
	ColorOut, ColorErr bool

	Record    func(activity.Event)
	cancelled bool
	// refused is set when run refuses a script: it exits 2, but is recorded as
	// denied rather than as a usage error.
	refused bool
	// ranCommand is set once run has run a command and is returning its exit code.
	ranCommand bool
	// endedBy is the signal that ended that command, if one did.
	endedBy syscall.Signal
}

const usage = `usage: keyward <command> [options]

Moves secrets out of your dotfiles into an encrypted vault and leaves cap://
references behind, so an AI agent reading the files finds nothing to leak.

commands:
  setup [file...]        first run, in Terminal.app: secrets, agents, MCP, recovery code
  migrate <file>         move a file's secrets into the vault (asks first)
  run -- <command>       run a command with the real values
  add <name>             store a secret read from stdin
  ls                     list stored names
  rm <name>              remove a secret
  doctor [file...]       check references, plaintext and exposed secrets, backups, and setup
  restore <file>...      put the values back into files (asks first)
  backups [rm|recover]   list, remove, or recover migrate's backups
  recovery show|restore  save or restore the vault's recovery code, in Terminal.app
  agents [link|unlink]   point AI agents at keyward's instructions, or stop
  mcp [wrap|unwrap]      run MCP servers through keyward, or stop
  status | stop | start  check, pause, or resume the daemon
  uninstall              undo everything keyward changed, then remove it (asks first)
  version

options:
  --dry-run              migrate, restore, uninstall: show what would change, and stop
  --force                add: replace an existing secret
  --all                  backups rm: remove every backup
  --purge                uninstall: also delete the vault and its Keychain key
  --only VAR,...         run: resolve only these variables
  --no-mask              run: do not hide the values in the command's output
  --allow-command-line   run, mcp wrap: allow a migrated secret in a program's command line

examples:
  keyward setup
  pbpaste | keyward add github-token
  keyward run --only GITHUB_TOKEN -- gh pr list
`

// Run dispatches a command and returns a process exit code.
func (c *CLI) Run(args []string) int {
	c.endedBy = 0
	// Ending as the command did waits until the command is recorded, since Die
	// does not return.
	defer func() {
		if c.endedBy != 0 && c.Die != nil {
			c.Die(c.endedBy)
		}
	}()
	args, hoisted := hoist(args)
	if hoisted && args[0] == "run" {
		// Moved after run, an option run does not know would be taken for the command.
		fmt.Fprint(c.Stderr, "keyward run's options go right after run: keyward run --only VAR -- <command>\n")
		return exitUsage
	}
	if c.Record == nil || len(args) == 0 {
		return c.dispatch(args)
	}
	command := args[0]
	if command == "--help" || command == "-h" {
		command = "help"
	}
	switch command {
	case "add", "ls", "rm", "run", "migrate", "restore", "backups", "agents", "recovery", "mcp", "setup", "doctor", "daemon", "service", "start", "stop", "status", "help", "version":
	default:
		return c.dispatch(args)
	}
	start := time.Now()
	store := c.Store
	c.cancelled, c.refused, c.ranCommand = false, false, false
	if store != nil {
		c.Store = &activity.Store{Store: store, Command: command, Record: c.Record}
	}
	defer func() { c.Store = store }()
	code := c.dispatch(args)
	outcome := "ok"
	if c.ranCommand {
		// The code is the command's own; a 2 from it is not a keyward usage error.
		if code != exitOK {
			outcome = "error"
		}
	} else if c.refused {
		outcome = "denied"
	} else if code == exitUsage {
		outcome = "usage"
	} else if c.cancelled {
		outcome = "cancelled"
	} else if code != exitOK {
		outcome = "error"
	}
	c.Record(activity.Event{Command: command, Operation: "command", Outcome: outcome, DurationMS: time.Since(start).Milliseconds()})
	return code
}

func (c *CLI) dispatch(args []string) int {
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
	case "restore":
		return c.restore(args[1:])
	case "backups":
		return c.backups(args[1:])
	case "agents":
		return c.agents(args[1:])
	case "recovery":
		return c.recovery(args[1:])
	case "mcp":
		return c.mcp(args[1:])
	case "setup":
		return c.setup(args[1:])
	case "doctor":
		return c.doctor(args[1:])
	case "daemon":
		return c.daemon(args[1:])
	case "start":
		// Start installs startup if needed, so one command covers first use and resuming.
		return c.runService("start", "install")
	case "stop", "status":
		return c.runService(args[0], args[0])
	case "service":
		return c.service(args[1:])
	case "uninstall":
		// Not recorded: logging afterwards would recreate the deleted log directory.
		return c.uninstall(args[1:])
	default:
		fmt.Fprintf(c.Stderr, "keyward: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func (c *CLI) service(args []string) int {
	if len(args) != 1 || !slices.Contains([]string{"install", "start", "stop", "status", "uninstall"}, args[0]) {
		fmt.Fprintln(c.Stderr, "usage: keyward service install|start|stop|status|uninstall")
		return exitUsage
	}
	if c.Service == nil {
		return c.fail("keyward service: service manager is unavailable")
	}
	if args[0] == "uninstall" {
		if _, err := fmt.Fprint(c.Stderr, c.errs(yellow, "Warning: while Keyward is stopped, cap:// references cannot be resolved.")+"\n\n"+
			"To put secrets back into your files first, cancel and restore the files you migrated:\n"+
			"  keyward restore --dry-run ~/.zshrc .env\n"+
			"  keyward restore ~/.zshrc .env\n"+
			"Restored files contain plaintext secrets again; check any skipped items.\n\n"+
			"Uninstall keeps the keyward command and your stored secrets. It does not restore files.\n\n"+
			c.errs(bold, `Type "yes" to stop the daemon and remove it from login startup:`)+" "); err != nil {
			return exitFailure
		}
		ok, err := c.readConfirmation()
		if err != nil {
			return c.fail("keyward service: could not read confirmation; automatic startup was kept")
		}
		if !ok {
			return c.cancel("Service uninstall cancelled. Automatic startup was kept.")
		}
	}
	return c.runService("service", args[0])
}

// runService performs a service action, naming command in any error.
func (c *CLI) runService(command, action string) int {
	if c.Service == nil {
		return c.fail("keyward %s: service manager is unavailable", command)
	}
	message, err := c.Service(action)
	if err != nil {
		return c.fail("keyward %s: %v", command, err)
	}
	fmt.Fprintln(c.Stdout, paintLines(c.ColorOut, message, map[string]string{"✓": green}))
	return exitOK
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
	names, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(names) != 1 {
		fmt.Fprint(c.Stderr, "usage: keyward add [-force] <name>\n")
		return exitUsage
	}
	name := names[0]

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

	// No provenance: a secret added by hand came from a person, not a file. That
	// absence is the signal that keeps `doctor` from ever calling it a leftover.
	if *force {
		// Replace requires the name to exist, so fall back to Put. -force means
		// "do not stop me", not "the name must already be there".
		if err := c.Store.Replace(name, secret, ""); err != nil {
			if !errors.Is(err, vault.ErrNotFound) {
				return c.fail("keyward add: %v", err)
			}
			if err := c.Store.Put(name, secret, ""); err != nil {
				return c.fail("keyward add: %v", err)
			}
		}
		return exitOK
	}

	if err := c.Store.Put(name, secret, ""); err != nil {
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
	entries, err := c.Store.Entries()
	if err != nil {
		return c.fail("keyward ls: %v", err)
	}
	for _, e := range entries {
		// Backup keys are keyward's own; `keyward backups` accounts for them.
		if !backup.IsKey(e.Name) {
			fmt.Fprintln(c.Stdout, e.Name)
		}
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

// daemon runs in the foreground so a Keychain prompt appears while someone is
// there to answer it.
func (c *CLI) daemon(args []string) int {
	if len(args) != 0 {
		fmt.Fprint(c.Stderr, "usage: keyward daemon\n")
		return exitUsage
	}
	if c.Daemon == nil {
		return c.fail("keyward daemon: not available in this build")
	}
	if err := c.Daemon(); err != nil {
		if errors.Is(err, daemon.ErrRunning) {
			return c.fail("keyward daemon: the daemon is already running, so there is nothing to start.\n  Check it with: keyward status")
		}
		return c.fail("keyward daemon: %v", err)
	}
	return exitOK
}

// run resolves every cap:// reference in the environment, or with --only just the
// named variables, and replaces this process with the requested command. When
// the command's stdout or stderr is not a terminal, keyward instead stays as its
// parent and hides the resolved values in that output, unless --no-mask, or no
// value it resolved is worth hiding.
//
// Before resolving, unless --allow-command-line, it refuses a shell's script, as
// in sh -c SCRIPT, that would put one of those values in another program's
// command line, where other programs and security logs can read it. The check
// needs only the variables' names, so a refused command never reads the vault.
//
// Resolution happens before anything is executed. If any reference fails, nothing
// runs — a command started with a literal cap:// value where a credential belongs
// fails in a way that looks like a bad token rather than a missing one.
func (c *CLI) run(args []string) int {
	const runUsage = "usage: keyward run [--only VAR,...] [--no-mask] [--allow-command-line] [--] <command> [arguments]\n"
	// Options are read only before the command; after it, they are the command's.
	var only []string
	noMask, allowCommandLine := false, false
	for len(args) > 0 && (args[0] == "--no-mask" || args[0] == "--allow-command-line" || args[0] == "--only" || strings.HasPrefix(args[0], "--only=")) {
		if args[0] == "--no-mask" {
			noMask, args = true, args[1:]
			continue
		}
		if args[0] == "--allow-command-line" {
			allowCommandLine, args = true, args[1:]
			continue
		}
		value, inline := strings.CutPrefix(args[0], "--only=")
		if !inline {
			if len(args) < 2 {
				fmt.Fprint(c.Stderr, runUsage)
				return exitUsage
			}
			value, args = args[1], args[1:]
		}
		args = args[1:]
		for _, key := range strings.Split(value, ",") {
			if key == "" {
				fmt.Fprint(c.Stderr, "keyward run: --only needs variable names, such as --only GITHUB_TOKEN\n")
				return exitUsage
			}
			only = append(only, key)
		}
	}
	// A leading -- is conventional and supported, but not required.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, runUsage)
		return exitUsage
	}

	env := c.Environ()
	// A misspelled name would otherwise run the command without its secret.
	for _, key := range only {
		if !slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, key+"=") }) {
			fmt.Fprintf(c.Stderr, "keyward run: --only names %s, which is not set\n", key)
			return exitUsage
		}
	}
	if !allowCommandLine && c.refuseScript(args, resolve.Variables(env, only)) {
		c.refused = true
		return exitUsage
	}
	result, err := resolve.New(c.Store).EnvOnly(env, only)
	if err != nil {
		return c.failResolve(err)
	}

	// Look the command up before exec so a typo is a clear message rather than an
	// opaque failure from the exec call.
	path, err := exec.LookPath(args[0])
	if err != nil {
		return c.fail("keyward run: %v", err)
	}

	if c.Record != nil {
		c.Record(activity.Event{Command: "run", Operation: "exec", Outcome: "started"})
	}
	if c.RunMasked != nil && !noMask && !(c.TerminalOut && c.TerminalErr) {
		if secrets := mask.Select(result.Values, plainValues(env)); len(secrets) > 0 {
			return c.runMasked(path, args, result.Env, secrets)
		}
	}
	if err := c.Exec(path, args, result.Env); err != nil {
		return c.fail("keyward run: executing %s: %v", args[0], err)
	}
	// Reached only when Exec is a test double; the real one does not return.
	return exitOK
}

// refuseScript says why, and returns true, when argv starts a shell whose script
// would put the value of one of vars in another program's command line, or run it
// as code, or names one in a script it cannot read. It never shows what the
// script holds, which could be a credential written into it.
func (c *CLI) refuseScript(argv, vars []string) bool {
	name, script, ok := shell.Command(argv)
	if !ok {
		return false
	}
	found, err := shell.Check(name, script, vars)
	if err == nil && len(found) == 0 {
		return false
	}
	// Run records the refusal after these writes.
	stop := catchSIGPIPE()
	defer stop()
	if err != nil {
		fmt.Fprintf(c.Stderr, "keyward run: cannot read the script %s -c runs, to check where its values go: %v\n  %s\n", name, err, shell.Hint(err))
	}
	for _, f := range found {
		fmt.Fprintf(c.Stderr, "keyward run: %s\n", f.Message())
		if advice := shell.Advice(f, found); advice != "" {
			fmt.Fprintf(c.Stderr, "  %s\n", advice)
		}
	}
	fmt.Fprint(c.Stderr, "  --allow-command-line runs it anyway, which an AI agent must not add unless the user asks.\n")
	return true
}

// runMasked runs a command with the values it was given hidden in its output,
// says which values it hid, and returns how the command ended; Run then ends
// the same way.
func (c *CLI) runMasked(path string, args, env []string, secrets []mask.Secret) int {
	exit, err := c.RunMasked(path, args, env, secrets)
	if err != nil {
		return c.fail("keyward run: executing %s: %v", args[0], err)
	}
	if exit.Err != nil && exit.Signal == syscall.SIGPIPE {
		// keyward closed the pipe when the destination failed, which ended the
		// command: fail with the cause, not by SIGPIPE, which says a reader went.
		exit.Code, exit.Signal = exitFailure, 0
	}
	c.ranCommand, c.endedBy = true, exit.Signal
	// Recorded before the notice, which a stderr that blocks may never let finish.
	if c.Record != nil {
		for _, name := range exit.Masked {
			c.Record(activity.Event{Command: "run", Operation: "mask", Name: name, Outcome: "ok"})
		}
	}
	// The stalled destination may be stderr, where writing more would block.
	if !exit.Stalled {
		c.maskNotice(args[0], exit)
	}
	if (exit.Err != nil || exit.Stalled) && exit.Code == exitOK {
		// The command succeeded, but not all of its output arrived.
		return exitFailure
	}
	return exit.Code
}

// maskNotice says on stderr what could not be passed on of a command's output,
// and which values were hidden in it.
func (c *CLI) maskNotice(command string, exit mask.Exit) {
	stop := catchSIGPIPE()
	defer stop()
	if exit.MidLine && (exit.Err != nil || len(exit.Masked) > 0) {
		fmt.Fprintln(c.Stderr)
	}
	if exit.Err != nil {
		fmt.Fprintf(c.Stderr, "keyward run: passing on the output of %s: %v\n", command, exit.Err)
	}
	if len(exit.Masked) == 0 {
		return
	}
	for _, name := range exit.Masked {
		fmt.Fprintf(c.Stderr, "keyward run: %s printed the value of %s, masked in the output\n", filepath.Base(command), name)
	}
	fmt.Fprint(c.Stderr, "  A command prints a secret when it gets it the wrong way, such as a curl user with no\n"+
		"  password, or is told to show it. If it was not meant to print it, change the command;\n"+
		"  do not look for the value. Output meant to carry the value, like a credential helper's,\n"+
		"  needs keyward run --no-mask, which an AI agent must not add unless the user asks.\n")
}

// catchSIGPIPE makes a write to a reader that has gone away fail, rather than end
// keyward before Run records the command, until the function it returns is called.
// Caught, not ignored: signal.Reset cannot undo Ignore.
func catchSIGPIPE() (stop func()) {
	pipe := make(chan os.Signal, 1)
	signal.Notify(pipe, syscall.SIGPIPE)
	return func() { signal.Stop(pipe) }
}

// plainValues returns the values in env that are not references.
func plainValues(env []string) []string {
	var plain []string
	for _, e := range env {
		if _, value, ok := strings.Cut(e, "="); ok && !handle.IsRef(value) {
			plain = append(plain, value)
		}
	}
	return plain
}

// migrate moves the secrets in a file into the vault and leaves references.
//
// The bare command shows the plan and then asks for confirmation, which must be
// the exact word "yes". --dry-run shows the plan and stops. -auto-approve applies
// without asking, for scripts.
//
// The plan goes to stdout and the question to stderr, so redirecting the plan to a
// file still leaves the question visible and answerable.
func (c *CLI) migrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	dryRun := fs.Bool("dry-run", false, "describe what would change, and stop")
	autoApprove := fs.Bool("auto-approve", false, "apply without asking for confirmation")
	paths, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if *dryRun && *autoApprove {
		// Guessing which was meant is how a script written to preview ends up
		// rewriting a shell config.
		fmt.Fprint(c.Stderr, "keyward migrate: -dry-run and -auto-approve contradict each other; pass one or neither\n")
		return exitUsage
	}
	if len(paths) != 1 {
		fmt.Fprint(c.Stderr, "usage: keyward migrate [--dry-run | -auto-approve] <file>\n")
		return exitUsage
	}

	plan, err := migrate.Read(paths[0])
	if err != nil {
		return c.fail("keyward migrate: %v", err)
	}

	// Before showing anything: reconcile against the vault, so a value that cannot
	// be stored appears as a skip in the plan rather than as a failure after the
	// user has already approved it.
	if err := plan.Check(c.Store); err != nil {
		return c.fail("keyward migrate: %v", err)
	}

	if plan.Empty() {
		fmt.Fprintf(c.Stdout, "%s: nothing to move\n", plan.Path)
		// If something was declined rather than merely uninteresting, say so.
		// Otherwise a secret left in plaintext looks like a clean result.
		for _, s := range plan.Blocked() {
			fmt.Fprintf(c.Stdout, "\n  line %d  %s\n    %s\n", s.Line, s.Name, s.Reason)
		}
		fmt.Fprint(c.Stdout, plan.Unmovable())
		return exitOK
	}

	// The plan is printed before anything else happens, so approval is never given
	// to something unseen. The diff withholds values; see migrate.Plan.Diff.
	fmt.Fprint(c.Stdout, paintLines(c.ColorOut, plan.Diff(), map[string]string{
		"@@": cyan, "-": red, "+": green, "not moved, check these yourself:": yellow,
		"credential-shaped text keyward cannot move:": yellow,
	}))

	if *dryRun {
		fmt.Fprintf(c.Stdout, "\n%s\n%s", c.out(cyan, "Dry run: nothing was changed."), runReminder(plan.Changes[0].Name))
		return exitOK
	}

	if !*autoApprove {
		ok, err := c.confirm(len(plan.Changes), plan.Path)
		if err != nil {
			return c.fail("keyward migrate: %v", err)
		}
		if !ok {
			fmt.Fprintln(c.Stderr)
			return c.cancel("Aborted. Nothing was changed.")
		}
	}

	applied, err := plan.Apply(c.Store, c.Backups)
	if err != nil {
		return c.fail("keyward migrate: %v", err)
	}
	c.recordRewrite(plan)
	// keyward does not run git, which may not be installed, so it cannot tell a
	// committed file from one never committed, such as a gitignored .env.
	if migrate.InGitRepository(plan.Path) {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("%s is in a git repository. If it was ever committed, the values it held are still in its history, where anyone with a copy can read them: "+
			"rotate them, then store each new value with keyward add --force NAME.", plan.Path)))
	}

	fmt.Fprintf(c.Stdout, "\n%s\n", c.out(green, fmt.Sprintf("Stored %d secret(s): %s", len(applied.Stored), strings.Join(applied.Stored, ", "))))
	fmt.Fprintf(c.Stdout, "Encrypted backup of the original: %s\n", applied.BackupPath)
	fmt.Fprintf(c.Stdout, "  Its key is in keyward's vault. Remove both once the new file works: keyward backups rm %s\n", plan.Path)
	if c.inSetup {
		return exitOK
	}
	fmt.Fprintf(c.Stdout, "\nOpen a new terminal, then start what needs these values through keyward, naming\n"+
		"the ones a command needs:\n"+
		"  keyward run --only %s -- <command>\n"+
		"Started any other way, a program sees the cap:// reference instead of the value.\n"+
		"MCP servers that use these values must start through keyward too: keyward mcp wrap changes them.\n", plan.Changes[0].Name)
	c.agentNextSteps()
	c.remindRecovery()
	return exitOK
}

// runReminder says what changes for programs once the values are references, with
// an example that names one, as keyward run without --only resolves them all.
func runReminder(name string) string {
	return "After migrating, start programs that read these variables through keyward run,\n" +
		"naming them, for example `keyward run --only " + name + " -- npm test`; otherwise\n" +
		"they see cap:// references.\n"
}

// confirmWord is the only accepted answer. Compared exactly, so a hurried "y" or a
// capitalised "Yes" does not rewrite a shell config.
const confirmWord = "yes"

// confirm asks whether to proceed, reporting false for any answer but "yes".
//
// Reaching end of input counts as a refusal. That is the case where nothing can
// answer — a pipeline, or an agent with no terminal — and applying there would be
// the worst possible default for a command that rewrites a file.
func (c *CLI) confirm(count int, path string) (bool, error) {
	fmt.Fprintf(c.Stderr, "\nMove %d value(s) out of %s and into keyward's encrypted vault?\n", count, path)
	fmt.Fprintf(c.Stderr, "  The file will be rewritten. The original is first saved to an encrypted backup.\n")
	fmt.Fprintf(c.Stderr, "  Afterwards, start commands that use these values as: keyward run --only VAR -- <command>\n")
	fmt.Fprintf(c.Stderr, "  %s\n\n  Enter a value: ", c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord)))
	return c.readConfirmation()
}

func (c *CLI) readConfirmation() (bool, error) {
	if c.Stdin == nil {
		c.cancelled = true
		return false, nil
	}
	if c.in == nil || c.inSrc != c.Stdin {
		c.in, c.inSrc = bufio.NewReader(c.Stdin), c.Stdin
	}
	line, err := c.in.ReadString('\n')
	fmt.Fprintln(c.Stderr)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("reading the answer: %w", err)
	}
	ok := strings.TrimSpace(line) == confirmWord
	if !ok {
		c.cancelled = true
	}
	return ok, nil
}

// doctor reports on the health of the setup: references with nothing behind them,
// credentials still in plaintext, and stored secrets nothing refers to.
//
// It never deletes. Removal stays a deliberate `keyward rm`, because doctor cannot
// prove a secret is unused — only that it did not find a reference in the files it
// read. The report prints the commands instead, which is one keystroke more than a
// flag and removes a whole category of accident.
func (c *CLI) doctor(args []string) int {
	paths := doctor.DefaultPaths(c.Home, c.Workdir)
	// Extra paths add to the defaults rather than replacing them: wider coverage
	// makes every "unreferenced" verdict more trustworthy.
	paths = append(paths, args...)

	servers := c.mcpServers()
	report, err := doctor.Run(c.Store, paths, servers)
	if err != nil {
		return c.fail("keyward doctor: %v", err)
	}

	fmt.Fprint(c.Stdout, report.String())
	problems := report.Problems()
	if !c.checkVaultOpens() {
		problems = append(problems, "the vault does not open")
	}
	if found, err := c.knownBackups(); err != nil {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not check for backups: %v", err)))
	} else if len(found) > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("\n%d backup(s) from migrate still hold old values; review them with keyward backups", len(found))))
	}
	c.remindRecovery()
	here, elsewhere, allowed, gone := c.checkServers(servers, false)
	for _, problem := range mcpProblems(append(here, elsewhere...)) {
		fmt.Fprintln(c.Stdout, c.out(yellow, "\n"+problem+"; see keyward mcp"))
		problems = append(problems, problem)
	}
	if len(allowed) > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, "\n"+allowedProblem(allowed)+"; see keyward mcp"))
	}
	if note := c.skippedNote(gone); note != "" {
		fmt.Fprintln(c.Stdout, "\n"+note)
	}
	if note := c.cursorNote(); note != "" {
		fmt.Fprintln(c.Stdout, "\n"+note)
	}
	if n := c.unlinkedAgents(); n > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("\n%d installed AI agent(s) do not read %s; run keyward agents link", n, agents.Display)))
	}
	var exposed []exposure.Exposure
	if c.Exposures != nil {
		exposed, err = c.Exposures()
	}
	if err != nil {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not check running programs for secrets: %v", err)))
	}
	for _, e := range exposed {
		fmt.Fprintln(c.Stdout, c.out(red, fmt.Sprintf("\n%s is in the command line of %s (pid %d), where any process can read it.\n"+
			"Start that program without it there (keyward mcp shows how for MCP servers), then rotate the secret.", e.Secret, e.Program, e.PID)))
	}
	if len(exposed) > 0 {
		problems = append(problems, fmt.Sprintf("%d secret(s) in a running program's command line", len(exposed)))
	}
	// Last, so it sums up every check above; the reminders are advice, not problems.
	if len(problems) > 0 {
		fmt.Fprintln(c.Stdout, c.out(red, "\nProblems found: "+strings.Join(problems, "; ")+"."))
		return exitFailure
	}
	fmt.Fprintln(c.Stdout, c.out(green, "\nNo problems found."))
	return exitOK
}

// mcpServers is loadAll, saying which configs it could not read.
func (c *CLI) mcpServers() []mcpconfig.Server {
	if c.Home == "" {
		return nil
	}
	servers, errs := c.loadAll()
	c.reportUnreadable(errs)
	return servers
}

// checkVaultOpens decrypts one stored value, since keyward ls lists names without
// the key and so cannot tell a vault that opens from one whose key is wrong.
func (c *CLI) checkVaultOpens() bool {
	entries, err := c.Store.Entries()
	if err != nil {
		return true // doctor.Run has already reported an unreachable store
	}
	for _, e := range entries {
		if backup.IsKey(e.Name) {
			continue
		}
		secret, err := c.Store.Get(e.Name)
		if err != nil {
			fmt.Fprintln(c.Stdout, c.out(red, fmt.Sprintf("\nThe vault does not open: %v", err)))
			return false
		}
		secret.Destroy()
		fmt.Fprintln(c.Stdout, "\nThe vault opens with its key.")
		return true
	}
	return true
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
	fmt.Fprintln(c.Stderr, c.errs(red, fmt.Sprintf(format, args...)))
	return exitFailure
}

// cancel reports a refusal the user chose, which is not an error.
func (c *CLI) cancel(message string) int {
	fmt.Fprintln(c.Stderr, c.errs(yellow, message))
	return exitFailure
}
