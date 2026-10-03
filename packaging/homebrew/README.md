# Keyward Homebrew tap

Keyward keeps secrets in the macOS Keychain and replaces plaintext values in
configuration files with `cap://name` references. Its local broker resolves those
references only when launching a command.

This formula builds Keyward from source. No paid Apple Developer membership is
required. It is macOS-only and uses Go and Apple's command line tools to build.

## Install

```sh
brew tap veilux-lab/tap
brew install veilux-lab/tap/keyward
keyward service install
keyward service status
```

Run startup commands as your normal user. The broker starts now and at login
through `brew services`. The signed native status app is not included.
Installation does not migrate secrets or modify shell startup files.
The fully qualified install command handles formula-specific trust on Homebrew
versions that require it. To install by short name instead, first run
`brew trust --formula veilux-lab/tap/keyward` when Homebrew requests trust.

Store values through standard input, then use references in your configuration.
See `keyward --help` for migration, restoration, and command examples. Never put a
secret value in a command argument.

## Upgrade

```sh
brew upgrade keyward
keyward service install
```

The second command restarts the broker. A changed source-built daemon may require
macOS approval to read previously stored Keychain items. Source builds do not
promise prompt-free upgrades.

## Uninstall

Before removing Keyward, run restoration explicitly if you want current stored
values returned to the files you migrated:

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env
keyward service uninstall
brew uninstall keyward
```

Choose your own migrated files. Restore previews the items and requires exact
`yes` before writing plaintext values. Service uninstall also warns and requires
`yes` before stopping startup. Keychain entries are retained. `brew uninstall`
does not automatically restore secrets or show Keyward's interactive warning.

## Logs

Activity metadata is in `~/Library/Logs/keyward/activity.jsonl`. Default history
is 30 days, capped at 50 MiB total. Secret values, child arguments, environment,
and child output are excluded. These are local activity logs, not a tamper-proof
audit trail.

## Switching from a signed local installation

Stop that installation with its `keyward service uninstall` before enabling
Homebrew startup. Ensure your PATH selects Homebrew's CLI rather than the old
`~/.local/bin/keyward`. Changing daemon builds may trigger Keychain approval.
