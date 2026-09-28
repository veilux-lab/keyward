// Command keyward keeps secrets out of what AI coding agents can read.
//
// Values live in the macOS Keychain; config files hold cap://<name> references
// instead. See `keyward help`.
package main

import (
	"os"
	"syscall"

	"github.com/nwokolo24/keyward/internal/cli"
	"github.com/nwokolo24/keyward/internal/vault"
)

func main() {
	// KEYWARD_SERVICE scopes the Keychain items to a different service name, so
	// the tool can be tried out without touching real entries.
	service := os.Getenv("KEYWARD_SERVICE")
	if service == "" {
		service = vault.DefaultService
	}

	c := &cli.CLI{
		Store:      vault.NewKeychainService(service),
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Environ:    os.Environ,
		ReadSecret: cli.StdinSecretReader(os.Stdin, os.Stderr),
		Exec:       syscall.Exec,
	}
	os.Exit(c.Run(os.Args[1:]))
}
