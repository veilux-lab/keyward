# Design

## Two layers, only one of which needs cooperation

| Layer | Provides | Needs the agent to cooperate? |
| --- | --- | --- |
| **Migration** — values move to the Keychain, files hold references | Security | No |
| **Cooperation** — MCP tools, generated agent instructions, useful errors | Productivity | Yes |

Keeping these separate is the central idea. If migration is done, the security
property holds whether or not the agent cooperates. Cooperation only decides
whether the agent gets its work done smoothly or wastes turns hunting for
credentials that are not there.

## Components

| Package | Responsibility | State |
| --- | --- | --- |
| `internal/handle` | Parse, validate, and format `cap://` references | Implemented |
| `internal/vault` | Keychain storage via cgo and Security.framework | Implemented |
| `internal/resolve` | Scan an environment, resolve references to values | Implemented |
| `internal/activity` | Private JSONL activity and bounded history | Implemented; 30 days / 50 MiB defaults |
| `internal/audit` | Tamper-evident audit history | Not started |
| `internal/migrate` | Detect secrets in a file, rewrite to references | Implemented |
| `internal/restore` | Return current referenced values to explicitly selected files | Implemented; exact `yes` required |
| `internal/mcpconfig` | Rewrite MCP server configs to launch via keyward | Not started |
| `cmd/keyward` | CLI surface | Implemented |
| `internal/daemon` | Own Keychain access behind a same-user socket | Implemented |
| `internal/doctor` | Report on references and stored metadata | Implemented |
| `internal/launchd` | Signed local installation and per-user startup | Implemented and tested on this Mac |

## The reference format

```text
cap://<name>
```

- Prefix matched **case-sensitively**, so detection is unambiguous and needs no
  allocation.
- Names are lowercased on parse. `cap://TOKEN` and `cap://token` are the same
  reference, which prevents two Keychain items differing only by case.
- Allowed characters: `a-z`, `0-9`, and the separators `-`, `_`, `.`. Must begin
  and end alphanumeric. Maximum 128 characters.
- Chosen to survive every parser that will see it: dotenv, JSON, YAML, TOML, and
  shell single-quoting. No `$`, no `{}`, no characters a shell will expand.

### Two decisions inside the parser worth keeping

**`IsRef` is weaker than `Parse`.** `IsRef` reports whether a string *claims* to
be a reference; `Parse` decides whether it is a valid one. A malformed reference
like `cap://bad name` returns true from `IsRef` and an error from `Parse`.

This matters because the alternative is worse. If a typo'd reference were treated
as "not a reference," it would be passed to a program as a literal value — a
silent failure in exactly the place the format exists to make safe. Callers
scanning an environment need "broken reference, fail loudly" to be distinct from
"literal value, pass through."

**Parse errors never quote their input.** `Parse` is routinely called on strings
that turn out to be real credentials, and an error message reaches a log file
easily. `ErrNotHandle` therefore carries no context at all. There is a test
asserting a token-shaped input never appears in the error text.

## Resolution paths

Ordered from least to most exposure. Prefer the first one that lets the work
finish. This ladder is borrowed from HASP, which got it right.

1. **`keyward run -- <cmd>`** — scan the environment, resolve references, exec
   the child. Values exist only in the child's environment.
2. **`keyward inject -- <cmd>`** — same, plus materialise a temporary file for
   tools that demand a credential path rather than a variable.
3. **`keyward shell`** — an interactive subshell holding real values. Explicit,
   time-boxed, and the only path where plaintext reaches the user's own
   environment.

`run` uses `syscall.Exec` rather than `exec.Command`: replacing the process image
leaves no parent holding secrets in memory and removes all child-management code.

### Why not lazy resolution in the rc file

The tempting shortcut is:

```sh
export TOKEN="$(keyward get TOKEN)"   # do not do this
```

This puts real values into the environment of *every* shell, which the agent's
own shell tool then inherits. It reintroduces the exact leak keyward exists to
close. References must stay references in the environment; only a deliberate
`run`, `inject`, or `shell` resolves them.

## What migrates, and what does not

keyward is a filter over the environment, not a replacement for it. `resolve`
acts only on values matching `cap://` and passes everything else through
byte-for-byte. Migration is opt-in per variable.

So ordinary exports are untouched and stay plaintext — `EDITOR`, `PATH`,
`AWS_PROFILE`, `LANG`, locale and tooling settings, anything that is not a
credential. There is no ambition to manage the whole environment.

A value is moved only on a specific signal: a known credential prefix, a
credential-like name, or a URL carrying a password. A value that merely looks
random is listed as possibly a secret and left in place. On a real `~/.zshrc`,
entropy alone picked `CPPFLAGS` and an ECR registry host, and moving those breaks
every build outside keyward. No list of safe names can be complete, so the user
decides these, with `keyward add` printed alongside.

Migration keeps a byte-for-byte backup of the original so a bad rewrite can be
undone exactly; `restore` rebuilds values but not the original quoting. Backups
live in a private directory rather than beside the file: a plaintext copy next to
`~/.zshrc` is exactly what an agent reading the home directory would find.

### Restoring before uninstall

`keyward restore [--dry-run] <file>...` reverses the current references in
explicitly selected files. Migration notes are provenance hints, not permission
to overwrite an old path. Values come from today's Keychain entries, including
manually added entries; historical values are not recoverable through this command.

The plan lists locations, variables, and reference names without retrieving
values. Applying requires the exact lowercase word `yes` after that plan and a
plaintext warning. Dry runs and refusals read no values. There is no bypass flag.

Restoration is best effort: unsupported syntax or file formats, missing or denied
items, and edits since the preview are reported and left alone. Shell values are
single-quoted without evaluating expansions. Dotenv values with ambiguous quoting
or escapes are refused. Files are replaced atomically, made private to the owner,
and retain owner execute permission. No backup of the restored values is created;
Keychain entries stay intact. Migrate backups of a fully restored file are removed:
they would be a second plaintext copy. A skip keeps them, since the backup may be
the only record of the skipped value. Any skip gives a nonzero exit status.

Restoration remains an explicit, separate command. `keyward service uninstall`
warns that references need a running daemon and shows restore/preview examples
before asking for lowercase `yes` to stop the daemon and remove startup. Refusing
keeps the service available so the user can restore first. Uninstall neither
retrieves values nor restores files, and retains the CLI, app, and Keychain items.
It also disables first-use startup until an explicit `keyward service install`.

### Secrets you want in an interactive shell

The harder case. A credential may be wanted at the prompt for ad-hoc work — for
example curling the Jira REST API with `$ATLASSIAN_MCP_AUTH`. Once migrated, that
variable holds a reference, and the request sends the literal string.

Three answers, in order of preference:

1. **`keyward shell`** — a time-boxed subshell holding real values, where the
   command works exactly as typed. This is the primary reason the command exists.
2. **A wrapper function** for anything done repeatedly.
3. **An explicit shell-visible list**, for a secret that genuinely must be
   plaintext in every shell. This forfeits the protection for those variables,
   which is occasionally the right trade. Keep the list short, deliberate, and
   documented; never make it the default.

### The expansion-order trap

Wrapper functions have a footgun worth stating once, clearly. 1Password documents
the same problem for `op run`:

```sh
# WRONG — the outer shell expands the variable before keyward runs,
# so curl receives the literal cap:// string
jira() { keyward run -- curl -H "Authorization: $ATLASSIAN_MCP_AUTH" "$@" }

# RIGHT — expansion happens inside the child, after resolution
jira() { keyward run -- sh -c 'curl -H "Authorization: $ATLASSIAN_MCP_AUTH" "$@"' _ "$@" }
```

`keyward doctor` should detect the wrong form where it can, because the failure
mode is a confusing 401 rather than an obvious error.

### Why the interactive/agent split holds

An agent's shell tool typically does not source `~/.zshrc` — reaching those
variables requires an explicit interactive invocation such as `zsh -ic`. So a
`keyward shell` session in a terminal and the agent's own shells are already
separate environments: real values can sit in one while the other sees only
references.

Migration closes both routes the agent had to the rc file's contents — reading
the file, and sourcing it via `zsh -ic`.

## Trust model: reference-only

The agent may **see** references and reason about them. It may not cause one to
be resolved. Requests go to a queue, a human approves, the command runs, and the
agent receives the command's *output* — never the value.

Rejected alternative: letting the agent invoke templated commands with the secret
injected (`use_capability("db", {query: ...})`). More capable, but its safety
depends on every command template being escape-proof forever. Reference-only
keeps the guarantee provable and deletes an entire class of vulnerability —
along with the SQL validator, the argument constrainer, and the template engine
that would have been needed to enforce it.

The cost is friction, and friction is the real risk to this project. Mitigations,
in order of importance:

- **Time-boxed grants.** One approval covers a short window rather than each
  call. This is a deliberate step toward the model just rejected; it stays
  defensible because a human made a bounded decision that is recorded.
- **Batched approval** rather than interrupting per request.
- **Plan-time approval** — agents already plan before acting, so approve the
  declared set of credentialed steps once.

## Storage: Keychain, not a custom vault

HASP writes its own encrypted vault with `golang.org/x/crypto` because it
supports Linux. keyward is macOS-only and therefore should not:

- No cryptography to implement, review, or get wrong.
- Per-item ACLs come free from the OS.
- Access-control flags open the door to biometric gating later.

Do not shell out to `/usr/bin/security`. `security add-generic-password -w
<value>` places the secret in `argv`, where `ps` can read it — self-defeating for
a secrets tool. Use cgo against `SecItemAdd` and `SecItemCopyMatching`.

### One process touches the Keychain

Keychain items trust the binary that created them, and an unsigned binary changes on
every build ([obstacles.md](obstacles.md) 2a). So `keyward daemon` is the only
process that calls the Keychain. Every other command asks it over a Unix socket that
only the same user can open. The CLI can be rebuilt freely. Unsigned daemon
rebuilds need per-item approval; rebuilding with the same Apple Development
certificate preserves access on the tested Mac.

The managed client starts the installed daemon only when a vault operation finds
the socket absent or refused. It then connects again before sending the request;
a request already sent is never replayed. Permission errors, timeouts, and other
connection failures do not start a second daemon. `Ping`, help, version, service
status, and commands with no vault calls remain checks without startup.

Homebrew starts an unloaded service with `brew services start`. A signed local
installation bootstraps its existing LaunchAgent; it never installs or signs a
development build on first use. Custom sockets or Keychain service names keep
manual startup. A private disabled marker records explicit service uninstall, so
first use cannot undo the user's choice. Explicit service install re-enables it.
These changes are prepared for the next source release.

Direct access from a separately built, equally signed command-line process was
also verified on 2026-10-02: it read, replaced, and deleted daemon-created dummy
items after their creator process exited. Signing therefore permits a simpler
CLI that owns its Keychain calls on this Mac. That is not the current production
path; removing the required daemon would need a cross-process lock and continued
activity logging. See [obstacles.md](obstacles.md) 2a for the repeatable test.

`keyward service install` copies a signed build into `~/.local/bin` and registers a
per-user LaunchAgent. launchd starts it at login and restarts it if it exits. Updates
replace the executable atomically, restart the agent, and check its socket without
reading a Keychain item. A failed startup restores the prior installation. Removing
the login agent keeps the CLI and stored items. `make install` still starts
the signed daemon immediately. The optional `brew keyward-install --start-daemon`
command installs the formula, waits for Homebrew to finish, then explicitly enables
startup. Normal Homebrew installation leaves startup for first use. Keeping this
outside a formula post-install hook preserves the user's home and avoids its
sandbox restrictions.

The signed installation contains the CLI and a per-user LaunchAgent. The daemon
keeps `com.nwokolo24.keyward` so existing Keychain access requirements still match.
`keyward service status` checks availability without reading secrets; `service
install` and `service uninstall` control startup. Activity is available in
`~/Library/Logs/keyward/activity.jsonl`. Signing still carries the certificate's
publisher identity.

The cost: any process running as the user can ask the daemon for any secret by
name, with no prompt. The Keychain ACL used to stop `/usr/bin/security` from
reading a keyward value, and now a request over the socket gets it. That fits the
cooperational model: the threat is an agent reading a file, not an agent working
against the tool deliberately (obstacle 1). The daemon logs every request by name,
so access can be seen, though nothing stops it.

### Activity retention

CLI commands and daemon requests share `activity.jsonl`. Events have only fixed
command/operation/outcome fields, successful canonical reference names, UTC time,
and duration. Failed names, arbitrary error text, provenance, values, environment,
child arguments, and output are excluded. CLI `run` records the exec attempt before
process replacement; it does not claim to know the child's exit status.

Defaults are 30 days and 50 MiB total, with daily or 10 MiB rotation. Cleanup runs
at CLI startup and event writes, so idle files may remain longer. The old
`daemon.log` counts as an archive using its modification time, without reading it.
An exclusive file lock protects append/rotation/cleanup across processes. Files
are opened relative to a checked private directory descriptor, without following
links; ownership, regular-file type, hard links, and permissions are checked.

Storage failures warn once in the CLI and operations continue. Configuration
errors fail before dispatch. Retention settings are saved into the LaunchAgent
on installation. This preserves activity visibility for a future direct CLI,
but same-user processes can edit or delete records; it is not a security boundary.

## MCP config rewriting

Each MCP server's launch command is rewritten to go through keyward, with
references in its `env` block:

```json
"splunk-mcp-server": {
  "command": "keyward",
  "args": ["run", "--", "uvx", "splunk-mcp-server"],
  "env": { "SPLUNK_MCP_TOKEN": "cap://splunk-mcp-token" }
}
```

This also fixes a real standing bug: MCP servers currently fail with a connect
timeout when the editor is launched from Finder rather than a terminal, because
`${SPLUNK_MCP_TOKEN}` is empty in a non-login environment. Resolving from the
Keychain makes the launch method irrelevant.

That fix matters out of proportion to its size. A tool kept installed for a daily
convenience is a tool whose security properties are still in force a year later.

## Testing approach

Test-driven throughout. Tests are written first and observed to fail before any
implementation exists.

cgo and the real Keychain resist unit testing, so the seam is an interface:

- `vault.Store` is an interface. All logic is tested against an in-memory fake.
- The cgo implementation stays thin enough to be nearly declarative.
- One build-tagged integration test exercises the real Keychain and is excluded
  from `make test`, keeping the default loop fast.

## Open design questions

- How a grant is represented and where its expiry is enforced.
- Whether the audit log needs signing, or whether append-only on a single-user
  machine is enough. Signing is cheap to add and hard to retrofit honestly.
- Whether biometric gating is reachable from a CLI process at all. See
  [obstacles.md](obstacles.md).
