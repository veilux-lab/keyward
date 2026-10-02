// Command keyward keeps secrets out of what AI coding agents can read.
//
// Values live in the macOS Keychain; config files hold cap://<name> references
// instead. See `keyward help`.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nwokolo24/keyward/internal/cli"
	"github.com/nwokolo24/keyward/internal/daemon"
	"github.com/nwokolo24/keyward/internal/launchd"
	"github.com/nwokolo24/keyward/internal/vault"
)

func main() {
	// KEYWARD_SERVICE scopes the daemon's Keychain items to a different service
	// name, and KEYWARD_SOCKET moves the socket, so the tool can be tried out
	// without touching real entries.
	service := os.Getenv("KEYWARD_SERVICE")
	if service == "" {
		service = vault.DefaultService
	}

	// Failures here are not fatal: doctor simply reports fewer files as scanned.
	home, _ := os.UserHomeDir()
	workdir, _ := os.Getwd()

	socket := os.Getenv("KEYWARD_SOCKET")
	if socket == "" {
		socket = daemon.DefaultSocket(home)
	}

	c := &cli.CLI{
		Store:      &daemon.Client{Path: socket},
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Environ:    os.Environ,
		ReadSecret: cli.StdinSecretReader(os.Stdin, os.Stderr),
		Exec:       syscall.Exec,
		Home:       home,
		Workdir:    workdir,
		Daemon: func() error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return daemon.Run(ctx, socket, vault.NewKeychainService(service), os.Stderr)
		},
		Service: func(action string) (string, error) {
			executable, err := os.Executable()
			if err != nil {
				return "", err
			}
			return (launchd.Manager{
				Home: home, Executable: executable, UID: os.Getuid(),
				Socket: socket, Service: service,
			}).Run(action)
		},
	}
	os.Exit(c.Run(os.Args[1:]))
}
