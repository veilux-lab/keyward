// Command keyward keeps secrets out of what AI coding agents can read.
//
// Values live in the macOS Keychain; config files hold cap://<name> references
// instead. See `keyward help`.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/cli"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/launchd"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/vault"
	"golang.org/x/term"
)

// Set by the Homebrew formula; local signed installations use launchd directly.
var homebrewExecutable string

func main() {
	daemon.Version = cli.Version
	// KEYWARD_SERVICE scopes the daemon's vault and Keychain key to a different
	// service name, KEYWARD_SOCKET moves the socket, and KEYWARD_VAULT the vault
	// file, so the tool can be tried out without touching real entries.
	service := os.Getenv("KEYWARD_SERVICE")
	if service == "" {
		service = vault.DefaultService
	}

	// Failures here are not fatal: doctor simply reports fewer files as scanned.
	home, _ := os.UserHomeDir()
	workdir, _ := os.Getwd()
	config, err := activity.FromEnv(home, os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyward:", err)
		os.Exit(2)
	}
	log, err := activity.New(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyward:", err)
		os.Exit(2)
	}
	var warning sync.Once
	warn := func(err error) {
		if err != nil {
			warning.Do(func() {
				fmt.Fprintln(os.Stderr, "keyward: activity logging unavailable; operation continues without a complete activity log")
			})
		}
	}
	warn(log.Clean())
	record := func(e activity.Event) { warn(log.Record(e)) }

	socket := os.Getenv("KEYWARD_SOCKET")
	if socket == "" {
		socket = daemon.DefaultSocket(home)
	}

	vaultPath := os.Getenv("KEYWARD_VAULT")
	if vaultPath == "" {
		vaultPath = vault.DefaultPath(home, service)
		// Before 1.1 the vault had a folder of its own. Best effort: on failure
		// the daemon creates a new vault, and the old one is still on disk.
		if err := vault.MoveLegacy(home, service); err != nil {
			fmt.Fprintln(os.Stderr, "keyward: could not move the vault into its new folder:", err)
		}
	}
	client := managedClient(home, socket, service, homebrewExecutable)
	c := &cli.CLI{
		Store:          client,
		Recovery:       client,
		RecoveryMarker: vaultPath + ".recovery-shown",
		Interactive:    term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())),
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		ColorOut:       cli.ColorEnabled(term.IsTerminal(int(os.Stdout.Fd())), os.Getenv),
		ColorErr:       cli.ColorEnabled(term.IsTerminal(int(os.Stderr.Fd())), os.Getenv),
		Environ:        os.Environ,
		ReadSecret:     cli.StdinSecretReader(os.Stdin, os.Stderr),
		Exec:           syscall.Exec,
		Home:           home,
		Workdir:        workdir,
		LookPath:       exec.LookPath,
		RunTool:        runTool,
		Self:           stablePath(home),
		Backups:        backup.Default(home),
		Record:         record,
		Daemon: func() error {
			if socket == daemon.DefaultSocket(home) && service == vault.DefaultService {
				// Best effort: a stale stop only makes first use ask for `service start`.
				_ = launchd.ClearStopped(home)
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			// Only the vault key lives in the Keychain; Legacy is where secrets were
			// kept before the vault, and they move in on first use.
			store := &vault.Encrypted{Path: vaultPath, Keys: vault.NewKeychainService(service + "-vault-key"), Legacy: vault.NewKeychainService(service)}
			return daemon.RunLogged(ctx, socket, store, record)
		},
		Service: func(action string) (out string, err error) {
			if action == "install" {
				defer func() {
					if err == nil {
						writeAgentFile(home)
					}
				}()
			}
			if homebrewExecutable != "" {
				if socket != daemon.DefaultSocket(home) || service != vault.DefaultService {
					return "", fmt.Errorf("Homebrew startup uses the default socket and Keychain service; run `keyward daemon` directly for an isolated instance")
				}
				return (launchd.Homebrew{Home: home, UID: os.Getuid(), Brew: homebrewExecutable}).Run(action)
			}
			executable, err := os.Executable()
			if err != nil {
				return "", err
			}
			return (launchd.Manager{
				Home: home, Executable: executable, UID: os.Getuid(),
				Socket: socket, Service: service,
				LogConfig: &config,
			}).Run(action)
		},
	}
	if socket == daemon.DefaultSocket(home) && service == vault.DefaultService {
		c.DataDirs = []string{filepath.Dir(socket), activity.DefaultConfig(home).Dir}
		c.Ledger = ledger.Default(home)
		ownFolder := vaultPath == vault.DefaultPath(home, service)
		if ownFolder {
			c.KeepDir = filepath.Dir(vaultPath)
		}
		c.PurgeVault = func() error { return purgeVault(vaultPath, service, ownFolder) }
		if homebrewExecutable != "" {
			c.RemovePackage = (launchd.Homebrew{Home: home, UID: os.Getuid(), Brew: homebrewExecutable}).Remove
		} else if executable, err := os.Executable(); err == nil && executable == filepath.Join(home, ".local", "bin", "keyward") {
			c.RemovePackage = (launchd.Manager{Home: home, UID: os.Getuid()}).Remove
		}
	}
	os.Exit(c.Run(os.Args[1:]))
}

// stablePath is the keyward path that survives upgrades, for configs keyward
// edits: Homebrew's bin link, not the versioned Cellar path os.Executable gives.
func stablePath(home string) string {
	if homebrewExecutable != "" {
		return filepath.Join(filepath.Dir(homebrewExecutable), "keyward")
	}
	if executable, err := os.Executable(); err == nil {
		return executable
	}
	return "keyward"
}

// runTool runs another tool's CLI, returning everything it printed.
func runTool(dir string, argv ...string) ([]byte, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

func managedClient(home, socket, service, brew string) *daemon.Client {
	client := &daemon.Client{Path: socket, Version: cli.Version}
	if socket != daemon.DefaultSocket(home) || service != vault.DefaultService {
		return client
	}
	if brew != "" {
		h := launchd.Homebrew{Home: home, UID: os.Getuid(), Brew: brew}
		client.Start, client.Restart = withAgentFile(home, h.Ensure), withAgentFile(home, h.Restart)
	} else {
		m := launchd.Manager{Home: home, UID: os.Getuid()}
		client.Start, client.Restart = withAgentFile(home, m.Ensure), withAgentFile(home, m.Restart)
	}
	return client
}

// withAgentFile writes the agent instructions when the daemon is first started or
// restarted after an upgrade. Homebrew's install step cannot: it is sandboxed away
// from the home directory.
func withAgentFile(home string, start func() error) func() error {
	return func() error {
		err := start()
		if err == nil {
			writeAgentFile(home)
		}
		return err
	}
}

// writeAgentFile is best effort; a file keyward did not write is left alone.
func writeAgentFile(home string) {
	if home != "" {
		_ = agents.Default(home).WriteRecorded(ledger.Default(home))
	}
}

// purgeVault deletes the vault, its recovery marker, its folder once empty, its
// key, and any secrets still stored as separate Keychain items. Deleting needs no
// Keychain approval.
func purgeVault(path, service string, ownFolder bool) error {
	var errs []error
	for _, file := range []string{path, path + ".recovery-shown"} {
		if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	// The vault folder, then keyward's, which uninstall has emptied around it. A
	// KEYWARD_VAULT elsewhere leaves its folders to their owner.
	var dirs []string
	if ownFolder {
		dirs = []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))}
	}
	for _, dir := range dirs {
		if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
			errs = append(errs, err)
		}
	}
	if err := vault.NewKeychainService(service + "-vault-key").Delete("master"); err != nil && !errors.Is(err, vault.ErrNotFound) {
		errs = append(errs, err)
	}
	legacy := vault.NewKeychainService(service)
	entries, err := legacy.Entries()
	errs = append(errs, err)
	for _, e := range entries {
		errs = append(errs, legacy.Delete(e.Name))
	}
	return errors.Join(errs...)
}
