# keyward

Keeps secrets out of what AI coding agents can read.

Agents read your shell rc file. Usually for ordinary reasons — checking `PATH`,
tracing why a variable is unset — and in doing so they pull every exported token
into their context. Nothing malicious happened, and the tokens are now in a
transcript.

keyward replaces those values with references:

```sh
# before
export SPLUNK_MCP_TOKEN=eyJraWQ...

# after
export SPLUNK_MCP_TOKEN='cap://splunk-mcp-token'
```

The value moves into the macOS Keychain. An agent reading `~/.zshrc`, or running
`env`, sees a reference. Commands that need the real value get it at execution
time:

```sh
keyward run -- npm test
```

## Why references instead of blocking reads

Blocking file reads means wrapping every agent, which means changing how you
launch each one, for every agent you use now and later. keyward asks nothing of
the agent: there is no plaintext to find, so nothing needs to be enforced.

This closes the accidental case, which is most of the real risk. It does not stop
an agent that deliberately sets out to obtain a credential — any process that can
run commands can run the resolver. Tools that claim otherwise on a developer
machine are usually overselling.

## Usage

```sh
# if automatic startup is not installed, leave the daemon running in a terminal
keyward daemon

# move the secrets in a shell rc file into the Keychain.
keyward migrate --dry-run ~/.zshrc   # describe what would move, change nothing
keyward migrate ~/.zshrc             # describe, then confirm by typing "yes"

# return referenced secrets to selected files; Keychain entries are kept
keyward restore --dry-run ~/.zshrc    # list items without reading secret values
keyward restore ~/.zshrc              # list items, then require explicit "yes"

# store one by hand — piped, so it never appears in argv or shell history
pbpaste | keyward add splunk-mcp-token

keyward ls                      # names only, never values
keyward rm splunk-mcp-token

# run a command with references resolved into its environment
keyward run -- npm test
```

Nothing else changes. `keyward` only touches values beginning with `cap://`;
`PATH`, `EDITOR`, and everything else passes through untouched, so migration is
opt-in per variable.

If a reference cannot be resolved, nothing runs and the error says what to do:

```text
keyward run: 1 reference(s) could not be resolved:
  SPLUNK_MCP_TOKEN=cap://splunk-mcp-token
    keychain get "splunk-mcp-token": secret not found
    add it with: keyward add splunk-mcp-token
```

Starting a command with a literal `cap://` string where a credential belongs would
fail as though the token were wrong rather than missing, so it is refused outright.

The daemon is the only Keychain caller, so CLI rebuilds never prompt. Daemon
upgrades signed with the same Apple Development certificate also preserve access
on the tested Mac. Unsigned daemon rebuilds still need per-item approval. The
daemon lets any process running as you ask for a secret by name.
See [doc/design.md](doc/design.md) for why that is acceptable here.

Set `KEYWARD_SERVICE` on the daemon to scope items to a different Keychain service
name, and `KEYWARD_SOCKET` on every command to use a separate socket. Together they
let you try it out without touching real entries.

## Install on this Mac

Requires Go 1.26.4+, Xcode command line tools, and an Apple Development certificate.
A free Personal Team certificate can be created through Xcode's account settings.
Find its exact identity, then build, sign, and install:

```sh
security find-identity -v -p codesigning
make install SIGN_IDENTITY='Apple Development: you@example.com (CERTIFICATE_ID)'
~/.local/bin/keyward service status
```

Allow codesign's signing-key prompt if it appears. Installation puts the CLI in
`~/.local/bin` and the **Keyward by Veilux** status app in `~/Applications/Keyward.app`.
It starts the daemon now and at login through a per-user LaunchAgent associated with
that app. Open the app to check status, view the activity log, or change automatic startup.
If that directory is not on your PATH, use `~/.local/bin/keyward` directly.
The installer does not edit shell startup files or migrate secrets.

Repeat the same command to upgrade using the same certificate. A failed startup
restores the previous app, binary, and login configuration. The app and daemon must
be signed by the same team. The daemon's existing signing identifier stays unchanged
to preserve Keychain access across upgrades.

Product branding does not change the signing certificate's publisher identity.
On this Mac, the existing Background App Activity entry still displays the personal
certificate name despite recording the app association; a fresh-machine notification
has not been tested. macOS may retain older attribution.

Daemon activity logs are in `~/Library/Logs/keyward/daemon.log`. They record UTC
timestamps, operations, reference names, outcomes, and startup/shutdown events.
Secret values are withheld. The directory is private to your user. These are basic
activity logs; rotation and a separate append-only audit trail are not implemented.

```sh
keyward restore --dry-run ~/.zshrc .env  # preview the files you want restored
keyward restore ~/.zshrc .env            # explicitly restore before uninstalling
keyward service uninstall               # warning, then confirm removal of startup
```

Uninstall warns you to run `keyward restore <file>...` first if you want the
secrets back in your files. It waits for lowercase `yes` before stopping the
daemon and removing automatic startup, giving you a chance to cancel and restore.
Restoration is a separate, explicit command; uninstall never restores secrets.
References need a running daemon to resolve. Check any restoration skips before
uninstalling or deleting the tool. The CLI, app, and Keychain entries are kept by
`service uninstall`. The status app shows this warning before disabling startup.

This installation is for personal use. Distribution requires a paid Developer ID
and remains untested. Certificate renewal and changes of team are also untested.

## Status

Working, with signed local installation and automatic daemon startup. There is no
notarised release or Homebrew formula. For an unsigned development build, use
`make build` and run `bin/keyward daemon` in a terminal.

Implemented:

- `keyward migrate` — move an rc file's secrets into the Keychain
- `keyward restore` — return referenced secrets to selected files after explicit approval
- `keyward add` / `ls` / `rm` / `run`
- `keyward daemon` — the single Keychain owner the other commands talk to
- macOS Keychain storage
- reference parsing and environment resolution

Next:

- MCP server config rewriting
- audit log

### On migrate

It always prints the plan first, then asks. Only the exact lowercase word `yes` is
accepted — not `y`, not `Yes`. `--dry-run` prints the plan and stops without asking,
so it is safe in a pipeline and safe for an agent to run. `-auto-approve` applies
without asking, for scripts. Asking for both `--dry-run` and `-auto-approve` is an
error rather than a guess.

Reaching end of input counts as a refusal, so a command with no terminal to answer
it aborts rather than rewriting the file.

Re-running is safe and incremental: already-migrated lines are recognised as
references and skipped, so only new entries move. Deleting a line from the file
leaves its secret in the Keychain, referenced by nothing — harmless, but
`keyward ls` accumulates. If that variable later reappears with a different value,
the plan says so and tells you to `keyward rm` the stale entry, rather than failing
part way through. The diff never shows a value, only its length — printing the old line
verbatim would spill every secret in the file into your scrollback, and into the
context of any agent that ran the command.

Before writing anything it stores each secret, so a failure never leaves the file
pointing at values that are not in the Keychain. The original is copied to a
timestamped backup beside it, the rewrite is atomic, and the file mode is
preserved. Running it twice is safe.

### On restore

`keyward restore [--dry-run] <file>...` uses the references currently in the
selected files and the values currently stored in the Keychain. This also works
for secrets added manually. It does not overwrite a file based on old migration
notes or recover a historical value.

The plan shows paths, line numbers, variable names, and reference names, never
values. `--dry-run` does not retrieve values. Actual restoration requires typing
`yes`; `y`, `Yes`, and end of input cancel. There is no approval-bypass flag.
The prompt explains that the files will contain plaintext secrets again.

Simple shell assignments and ordinary dotenv values are supported. Unsupported
syntax, JSON/TOML files, missing secrets, denied reads, and files edited after the
preview are skipped. References within multiline quoted text or continued
commands are skipped; references after a heredoc are left for manual restoration.
Dotenv values containing single quotes, backslashes, or newlines
are skipped when their interpretation could depend on the dotenv parser. The
command exits unsuccessfully if anything is skipped, even if other items were
restored successfully.

Writes are atomic and private to your user (mode `600`, or `700` when preserving
the owner's execute permission). Unrelated lines remain unchanged. Keychain
entries are retained, and restoration makes no backup containing the restored
values. Review the reported skips before removing Keyward.

## Development

Requires Go 1.26+ and the Xcode command line tools (for cgo).

```sh
make test
make vet
make cover
```

## License

MIT — see [LICENSE](LICENSE).
