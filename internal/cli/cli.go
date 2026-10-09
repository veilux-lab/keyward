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
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/migrate"
	"github.com/veilux-lab/keyward/internal/resolve"
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

	// Home and Workdir locate the files doctor reads by default. Fields rather than
	// calls to os.UserHomeDir and os.Getwd so a test can point them at a temp
	// directory instead of the developer's own configuration.
	Home    string
	Workdir string

	// Daemon serves the Keychain to the other commands until interrupted.
	// Injected because it binds a socket and owns the real Keychain.
	Daemon func() error

	// Backups holds migrate's private plaintext copies of the originals.
	Backups backup.Dir

	// DataDirs are deleted by uninstall; empty for isolated instances.
	DataDirs []string
	// RemovePackage deletes the installed program after its data; nil for development builds.
	RemovePackage func() (string, error)

	// Service manages the signed installation and login agent.
	Service func(action string) (string, error)

	// ColorOut and ColorErr enable ANSI colour on each stream; see ColorEnabled.
	ColorOut, ColorErr bool

	Record    func(activity.Event)
	cancelled bool
}

const usage = `usage: keyward <command> [arguments]

Secrets live in the macOS Keychain. Config files hold cap://<name> references
instead of values, so an agent reading them finds nothing worth having.

Only a background daemon touches the Keychain; the other commands ask it. An
installed daemon starts on first use and at login. Start it now, or re-enable it,
with keyward service install.

commands:
  service install       install or restart daemon startup at login
  service start         start the daemon after service stop
  service stop          stop the daemon until service start or next login
  service status        check whether the daemon is running
  service uninstall     warn about restoration, then ask to remove startup
  uninstall             remove startup, local data, backups, and the package
                        (asks first; Keychain items are kept)
  add [-force] <name>   store a secret read from stdin
  ls                    list stored secret names
  rm <name>             remove a secret
  run [--] <cmd>...     resolve cap:// references and run a command
  migrate <file>        move a file's secrets into the Keychain (asks first)
  migrate --dry-run <f> describe what would move, and stop
  restore <file>...     return referenced secrets to files (requires "yes")
  restore --dry-run <f> preview restoration without reading secret values
  backups               list migrate's encrypted backups
  backups rm <file>...  remove backups of files, and their keys (or --all)
  backups recover <f>   write a file's latest backup beside it, in plaintext
  doctor [file...]      check references against what is stored
  version               print the version
  help                  print this message

advanced:
  daemon                run the Keychain daemon in this terminal; installed copies
                        start it for you, so use this only for development builds

Options may go before or after a command's arguments; -- ends them. Everything
after run's command belongs to that command.

examples:
  pbpaste | keyward add splunk-mcp-token
  keyward run -- npm test
  keyward migrate --dry-run ~/.zshrc   # describe, change nothing
  keyward migrate ~/.zshrc             # describe, then confirm with "yes"
  keyward restore ~/.zshrc             # list, then confirm plaintext restoration

logging:
  ~/Library/Logs/keyward/activity.jsonl (metadata only)
  30 days, 50 MB total; rotate daily or at 10 MB by default
  KEYWARD_LOG_RETENTION_DAYS, KEYWARD_LOG_MAX_MB, KEYWARD_LOG_ROTATE_MB
`

// Run dispatches a command and returns a process exit code.
func (c *CLI) Run(args []string) int {
	args, hoisted := hoist(args)
	if hoisted && args[0] == "run" {
		// Options after run belong to the child command, so none can go before it.
		fmt.Fprint(c.Stderr, "keyward run takes no options; put the command's own options after it\n")
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
	case "add", "ls", "rm", "run", "migrate", "restore", "backups", "doctor", "daemon", "service", "help", "version":
	default:
		return c.dispatch(args)
	}
	start := time.Now()
	store := c.Store
	c.cancelled = false
	if store != nil {
		c.Store = &activity.Store{Store: store, Command: command, Record: c.Record}
	}
	defer func() { c.Store = store }()
	code := c.dispatch(args)
	outcome := "ok"
	if code == exitUsage {
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
	case "doctor":
		return c.doctor(args[1:])
	case "daemon":
		return c.daemon(args[1:])
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
			"Uninstall keeps the keyward command and your Keychain items. It does not restore files.\n\n"+
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
	message, err := c.Service(args[0])
	if err != nil {
		return c.fail("keyward service: %v", err)
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
			return c.fail("keyward daemon: the daemon is already running, so there is nothing to start.\n  Check it with: keyward service status")
		}
		return c.fail("keyward daemon: %v", err)
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

	if c.Record != nil {
		c.Record(activity.Event{Command: "run", Operation: "exec", Outcome: "started"})
	}
	if err := c.Exec(path, args, result.Env); err != nil {
		return c.fail("keyward run: executing %s: %v", args[0], err)
	}
	// Reached only when Exec is a test double; the real one does not return.
	return exitOK
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
		return exitOK
	}

	// The plan is printed before anything else happens, so approval is never given
	// to something unseen. The diff withholds values; see migrate.Plan.Diff.
	fmt.Fprint(c.Stdout, paintLines(c.ColorOut, plan.Diff(), map[string]string{
		"@@": cyan, "-": red, "+": green, "not moved, check these yourself:": yellow,
	}))

	if *dryRun {
		fmt.Fprintf(c.Stdout, "\n%s\n%s", c.out(cyan, "Dry run: nothing was changed."), runReminder)
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

	fmt.Fprintf(c.Stdout, "\n%s\n", c.out(green, fmt.Sprintf("Stored %d secret(s): %s", len(applied.Stored), strings.Join(applied.Stored, ", "))))
	fmt.Fprintf(c.Stdout, "Encrypted backup of the original: %s\n", applied.BackupPath)
	fmt.Fprintf(c.Stdout, "  Its key is in the Keychain. Remove both once the new file works: keyward backups rm %s\n", plan.Path)
	fmt.Fprint(c.Stdout, "\nOpen a new terminal, then start what needs these values through keyward:\n"+
		"  keyward run -- npm test\n  keyward run -- code .    # an editor, and the tools it starts\n"+
		"Started any other way, a program sees the cap:// reference instead of the value.\n")
	return exitOK
}

// runReminder says what changes for programs once the values are references.
const runReminder = "After migrating, programs that read these variables must start through\n" +
	"keyward run, for example `keyward run -- npm test`; otherwise they see cap:// references.\n"

// confirmWord is the only accepted answer. Compared exactly, so a hurried "y" or a
// capitalised "Yes" does not rewrite a shell config.
const confirmWord = "yes"

// confirm asks whether to proceed, reporting false for any answer but "yes".
//
// Reaching end of input counts as a refusal. That is the case where nothing can
// answer — a pipeline, or an agent with no terminal — and applying there would be
// the worst possible default for a command that rewrites a file.
func (c *CLI) confirm(count int, path string) (bool, error) {
	fmt.Fprintf(c.Stderr, "\nMove %d value(s) out of %s and into the Keychain?\n", count, path)
	fmt.Fprintf(c.Stderr, "  The file will be rewritten. The original is first saved to an encrypted backup.\n")
	fmt.Fprintf(c.Stderr, "  Afterwards, start commands that use these values as: keyward run -- <command>\n")
	fmt.Fprintf(c.Stderr, "  %s\n\n  Enter a value: ", c.errs(bold, fmt.Sprintf("Only %q will be accepted.", confirmWord)))
	return c.readConfirmation()
}

func (c *CLI) readConfirmation() (bool, error) {
	if c.Stdin == nil {
		c.cancelled = true
		return false, nil
	}
	line, err := bufio.NewReader(c.Stdin).ReadString('\n')
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
// and stored secrets nothing refers to.
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

	report, err := doctor.Run(c.Store, paths)
	if err != nil {
		return c.fail("keyward doctor: %v", err)
	}

	fmt.Fprint(c.Stdout, report.String())
	if found, err := c.knownBackups(); err != nil {
		fmt.Fprintln(c.Stderr, c.errs(yellow, fmt.Sprintf("Could not check for backups: %v", err)))
	} else if len(found) > 0 {
		fmt.Fprintln(c.Stdout, c.out(yellow, fmt.Sprintf("\n%d backup(s) from migrate still hold old values; review them with keyward backups", len(found))))
	}
	if report.HasProblems() {
		return exitFailure
	}
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
	fmt.Fprintln(c.Stderr, c.errs(red, fmt.Sprintf(format, args...)))
	return exitFailure
}

// cancel reports a refusal the user chose, which is not an error.
func (c *CLI) cancel(message string) int {
	fmt.Fprintln(c.Stderr, c.errs(yellow, message))
	return exitFailure
}
