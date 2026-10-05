# Using Keyward

For Homebrew setup, upgrades, and removal, see [homebrew.md](homebrew.md).
First-use startup and CLI-only installation are available from `v0.1.3`. With
Homebrew `v0.1.1`, start the daemon with `keyward service install` first.
With a development build, run `bin/keyward daemon` in a terminal.

## Daemon startup

An installed CLI starts its managed daemon when a command first needs the
Keychain and the socket is absent. This includes listing names and checking
migration or restoration metadata, even during a dry run. A command that does
not use the Keychain, such as `run` with no references, does not start it.
Help, version, status, and health checks do not start it either.

Homebrew starts its service through `brew services`; a signed local CLI starts
the LaunchAgent that was already installed. Once enabled, launchd starts the
daemon at login and keeps it running. This does not install or sign a development
build. Permission errors and an unresponsive daemon are reported without starting
a second process or replaying a request.

`keyward service uninstall` disables first-use startup as well as login startup.
The choice is saved in a private local marker. Use `keyward service install` to
enable startup again. The signed `make install` continues to start the daemon
immediately.

Custom `KEYWARD_SOCKET` or `KEYWARD_SERVICE` values use manual startup, so isolated
experiments never start your normal daemon. Set the service on the daemon and
the socket on every command, then run `keyward daemon` yourself.

## Everyday commands

```sh
pbpaste | keyward add api-token   # read the value from standard input
keyward ls                       # list names, never values
keyward doctor                   # check references and unused entries
keyward rm api-token             # delete a stored item
keyward run -- npm test           # resolve references in the child's environment
```

Never put a secret value in a command argument. Arguments can appear in process
listings and shell history. `add` reads standard input instead.

`run` resolves environment values beginning with `cap://`; ordinary values pass
through unchanged. If any reference cannot be resolved, the child command does
not start. References in other files, such as an application's JSON config, are
not automatically resolved.

Shell expansions happen before Keyward starts. Use programs or scripts that read
their environment when they run, rather than expanding secret variables in the
outer shell's command arguments.

## Migrate a file

```sh
keyward migrate --dry-run ~/.zshrc
keyward migrate ~/.zshrc
```

Migration supports simple shell assignments and ordinary dotenv files. It looks
for credential prefixes, credential-like variable names, and URLs containing
passwords. Uncertain syntax and values that only look random are left for you to
review. It does not move every environment variable.

The preview shows names and locations without printing values. Applying requires
exact lowercase `yes`; `y`, `Yes`, and end of input cancel. `--dry-run` changes
nothing. Scripts can use `-auto-approve`; it cannot be combined with `--dry-run`.

Secrets are stored before the file is rewritten. The rewrite is atomic and
preserves the file mode. A timestamped backup beside the original still contains
plaintext secrets: keep it only as long as you need it. Open a new terminal after
migration so exported variables contain references rather than the old values.

Re-running migration skips existing references. Removing a line does not delete
its Keychain item. If a variable returns with a different value, migration asks
you to remove the stale item with `keyward rm` first.

## Restore selected files

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env
```

Restoration uses the references in the selected files and the values currently
stored in the Keychain, including manually added items. It does not recover old
values or overwrite files using migration history.

The preview lists locations, variables, and names without retrieving values.
Actual restoration requires exact lowercase `yes` after a warning that plaintext
will return to the files. There is no approval-bypass flag.

Simple shell assignments and ordinary dotenv values are supported. Unsupported
syntax, JSON/TOML files, missing or denied items, and files changed after the
preview are skipped. Multiline quoted text and continued commands are skipped;
references after a heredoc are left for manual restoration. Dotenv values with
single quotes, backslashes, or newlines may be refused when their interpretation
depends on the dotenv parser. Any skip gives a nonzero exit status, even if other
items were restored.

Writes are atomic and private to your user: mode `600`, or `700` when preserving
your execute permission. Unrelated lines are unchanged. Keychain items remain,
and restoration does not create another backup containing the restored values.

Restore before stopping the daemon if you want plaintext values back. Check all
reported skips before removing Keyward. `keyward service uninstall` warns and
requires `yes` before stopping startup; it keeps the CLI and Keychain items.
It does not restore files. First-use startup stays disabled until you explicitly
enable it again with `keyward service install`.

## Signed local installation

Requires Go 1.26.4+, Xcode command line tools, and an Apple Development certificate.
A free Personal Team certificate can be created through Xcode's account settings.
Development verification (`make verify`) also requires Python 3.
Find its exact identity, then build, sign, and install:

```sh
security find-identity -v -p codesigning
make install SIGN_IDENTITY='Apple Development: you@example.com (CERTIFICATE_ID)'
~/.local/bin/keyward service status
```

Allow codesign's signing-key prompt if it appears. Installation puts the CLI in
`~/.local/bin` and starts the daemon now and at login through a per-user
LaunchAgent. Use `keyward service status` to check it, `keyward service install`
to enable or restart it, and `keyward service uninstall` to disable startup.
Activity is recorded in `~/Library/Logs/keyward/activity.jsonl`.
If the CLI directory is not on your PATH, use `~/.local/bin/keyward` directly.
Installation does not edit shell files or migrate secrets.

Repeat the same command to upgrade using the same certificate. A failed startup
restores the previous binary and login configuration. The daemon keeps its
signing identifier to preserve Keychain access across upgrades.

Rebuilds signed with the same Apple Development certificate retained access on
the tested Mac. Certificate renewal, changes of team, and Developer ID-signed
distribution remain untested. Actual logout/login and fresh-machine background
notifications are also untested. macOS may display the certificate owner's name
in Background App Activity.

This installation is for personal use. Prebuilt Developer ID-signed and notarized
distribution requires paid Apple membership. Source-built Homebrew distribution
does not.

## Activity logs

CLI and daemon activity is recorded in
`~/Library/Logs/keyward/activity.jsonl`. Records contain UTC timestamps, command
and operation names, successful reference names, fixed outcomes, and durations.
They omit values, rejected inputs, provenance, environment variables, child
arguments, and output. `run` records the execution attempt; it cannot record the
child's eventual exit status.

Defaults are **30 days and 50 MiB total**, removing oldest history when either
limit is reached. Files rotate daily or before exceeding 10 MiB. Cleanup happens
at CLI startup and on event writes, so idle files remain until the next use.
The log directory is mode `700`; files are mode `600`. A file lock coordinates
appends, rotation, and cleanup. Unsafe ownership, permissions, and links are
refused. An old `daemon.log` counts toward the same limits by modification time;
its contents are not read or converted.

Optional settings use MiB despite the `MB` names:

```sh
export KEYWARD_LOG_RETENTION_DAYS=7
export KEYWARD_LOG_MAX_MB=20
export KEYWARD_LOG_ROTATE_MB=5
```

CLI settings apply immediately. For the signed installation, rerun
`keyward service install` to persist them for the daemon. Homebrew's daemon uses
the defaults. `KEYWARD_LOG_DIR` selects a different log directory for isolated
tests.

Invalid settings fail before a command runs. A storage failure warns once per CLI
process and lets the operation continue. Names reveal service-use metadata, and
any process running as you can read or alter these files. They are activity logs,
not a tamper-proof audit trail.

For isolated experiments, set `KEYWARD_SERVICE` on the daemon and
`KEYWARD_SOCKET` on every command to avoid your regular items and socket.
