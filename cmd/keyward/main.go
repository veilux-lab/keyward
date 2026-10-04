// Command keyward keeps secrets out of what AI coding agents can read.
//
// Values live in the macOS Keychain; config files hold cap://<name> references
// instead. See `keyward help`.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/cli"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/launchd"
	"github.com/veilux-lab/keyward/internal/vault"
)

// Set by the Homebrew formula; local signed installations use launchd directly.
var homebrewExecutable string

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

	c := &cli.CLI{
		Store:      managedClient(home, socket, service, homebrewExecutable),
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Environ:    os.Environ,
		ReadSecret: cli.StdinSecretReader(os.Stdin, os.Stderr),
		Exec:       syscall.Exec,
		Home:       home,
		Workdir:    workdir,
		Record:     record,
		Daemon: func() error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return daemon.RunLogged(ctx, socket, vault.NewKeychainService(service), record)
		},
		Service: func(action string) (string, error) {
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
	os.Exit(c.Run(os.Args[1:]))
}

func managedClient(home, socket, service, brew string) *daemon.Client {
	client := &daemon.Client{Path: socket}
	if socket != daemon.DefaultSocket(home) || service != vault.DefaultService {
		return client
	}
	if brew != "" {
		client.Start = (launchd.Homebrew{Home: home, UID: os.Getuid(), Brew: brew}).Ensure
	} else {
		client.Start = (launchd.Manager{Home: home, UID: os.Getuid()}).Ensure
	}
	return client
}
