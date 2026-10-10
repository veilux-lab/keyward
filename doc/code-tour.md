# Code tour

How keyward works, for engineers who want to understand it, review it, or explain
it to someone else. Read top to bottom; each section names the code to open next.

## The one-paragraph version

AI coding agents read shell startup files and `.env` files for ordinary reasons,
and pull every exported token into their context. keyward moves those values into
an encrypted vault and leaves a reference in the file:

```sh
# before
export GITHUB_TOKEN=ghp_…
# after
export GITHUB_TOKEN='cap://github-token'
```

An agent reading the file, or running `env`, sees `cap://github-token`. A command
that needs the real value is started as `keyward run -- gh pr list`, which swaps
references for values in that one process's environment and nowhere else.

keyward is cooperative, not an enforcement tool. It removes the accidental leak, a
plaintext secret sitting where tools read. It does not stop a program running as
you that sets out to get a secret, because that program can run `keyward run`
too. See [mission.md](mission.md) for why that line is drawn there.

## The picture

```text
 ~/.zshrc, .env                keyward CLI                    keyward daemon
 ┌───────────────────┐   ┌──────────────────────┐   socket   ┌──────────────────────┐
 │ TOKEN='cap://tok' │──▶│ run: resolve refs,   │──────────▶│ same-user check      │
 └───────────────────┘   │      exec the child  │  JSON req  │ vault.Encrypted      │
                         │ migrate, add, rm, ls │◀──────────│   │                   │
                         └──────────────────────┘            │   ▼                   │
                                                             │ keyward.vault  (file) │
                                                             │ vault key (Keychain)  │
                                                             └──────────────────────┘
```

Three pieces:

1. **References** (`cap://name`) in files and environments. Not secret.
2. **The CLI**, which every command goes through. It never touches the Keychain.
3. **The daemon**, a long-lived per-user process and the only thing that reads
   the vault or its key.

## 1. References: `internal/handle`

Open [internal/handle/handle.go](../internal/handle/handle.go).

- A reference is `cap://` plus a name: lowercase letters, digits, `-`, `_`, `.`,
  starting and ending alphanumeric, at most 128 characters. It survives dotenv,
  JSON, YAML, TOML and shell quoting, with nothing a shell would expand.
- `Normalize` is the single definition of a valid name; the vault and the parser
  both use it.
- `IsRef` is deliberately weaker than `Parse`. `cap://bad name` *claims* to be a
  reference but is invalid, and keyward fails loudly on it instead of passing the
  literal string to a program as if it were a value.
- Parse errors never quote their input, because the input is often a real
  credential and error text ends up in logs.

## 2. Moving secrets: `keyward migrate`

Open [internal/migrate](../internal/migrate) in this order.

1. **[scan.go](../internal/migrate/scan.go)**: `Scan` splits a file into simple
   assignments it understands, and can reproduce the file byte for byte. Anything
   it cannot parse with certainty is left alone. A missed secret is just the
   status quo; a mangled line breaks someone's shell.
2. **[detect.go](../internal/migrate/detect.go)**: `Detect` decides whether a value
   is a secret, and always says why. It moves a value only on a specific signal: a
   known credential prefix (`ghp_`, `eyJ`, `-----BEGIN `…), a credential-like name
   (`TOKEN`, `SECRET`, `PW`…), or a URL with a password. Values with shell
   expansions, paths, and short values are left alone. A value that merely looks
   random is listed for the user to decide, never moved: on a real `~/.zshrc`,
   entropy alone flagged `CPPFLAGS`.
3. **[migrate.go](../internal/migrate/migrate.go)**: `NewPlan` builds the change
   list; `Plan.Apply` does it, in an order chosen so a failure loses nothing:
   - store every value in the vault;
   - save an encrypted backup of the original;
   - rewrite the file atomically, keeping its mode.

The CLI side is `migrate` in [internal/cli/cli.go](../internal/cli/cli.go). It
prints the plan with values withheld, showing only their length, because printing
the old lines would put every secret into scrollback and into the context of any
agent that ran the command. It then accepts only the exact word `yes`; end of
input counts as no, so a pipeline or an agent cannot apply it by accident.

## 3. Using secrets: `keyward run`

Open `run` in [internal/cli/cli.go](../internal/cli/cli.go), then
[internal/resolve/resolve.go](../internal/resolve/resolve.go).

1. `resolve.Env` scans the environment, resolves every `cap://` value through the
   vault, and passes everything else through byte for byte.
2. Resolution is all or nothing. A half-resolved environment runs a command with
   some real values and some literal references, which fails like a bad token
   rather than a missing one. Every failure is reported at once, each with the
   command that fixes it.
3. `run` then calls `syscall.Exec`: keyward *becomes* the command. No parent
   process is left holding the values, and there is no child management.

The one trap worth knowing: the outer shell expands variables before keyward runs.

```sh
keyward run -- curl -H "Authorization: $TOKEN" …           # sends cap://…
keyward run -- sh -c 'curl -H "Authorization: $TOKEN" …'   # resolved first
```

## 4. The daemon: `internal/daemon`

**Why it exists.** A Keychain item is tied to the program that created it. An
unsigned or Homebrew-built program is identified by its exact bytes, so every
rebuild looked like a stranger and stopped on an approval dialog. Making one
long-lived process the only Keychain caller lets the CLI change freely. The full
history is in [obstacles.md](obstacles.md), section 2a.

Open in this order:

- **[protocol.go](../internal/daemon/protocol.go)**: one JSON request per
  connection, one response, at most 1 MiB. Errors cross the socket as codes, so
  the client can still use `errors.Is(err, vault.ErrNotFound)`.
- **[listen.go](../internal/daemon/listen.go)**: the socket lives at
  `~/Library/Application Support/keyward/daemon.sock`. A lock file beside it makes
  the daemon single-instance.
- **[peer_darwin.go](../internal/daemon/peer_darwin.go)**: each connection's user
  is read from the kernel (`LOCAL_PEERCRED`), not from anything the client says.
  Only the daemon's own user is served.
- **[server.go](../internal/daemon/server.go)**: dispatches requests to a
  `vault.Store` and records each one in the activity log, by name only.
- **[client.go](../internal/daemon/client.go)**: `daemon.Client` implements
  `vault.Store`, so the CLI cannot tell it apart from a local store. It starts the
  installed daemon on first use, and restarts it once when it is an older version,
  since Homebrew leaves the old daemon running across an upgrade.

## 5. Storage: `internal/vault`

Start with the interface in [store.go](../internal/vault/store.go): `Get`, `Put`
(never overwrites), `Replace`, `Delete`, `Entries` (names and notes, never
values). Three implementations are held to the same contract suite in
[vaulttest](../internal/vault/vaulttest/vaulttest.go):

| Implementation | Used for |
| --- | --- |
| `Memory` ([memory.go](../internal/vault/memory.go)) | every unit test above the vault |
| `Encrypted` ([encrypted.go](../internal/vault/encrypted.go)) | what the daemon serves |
| `Keychain` ([keychain_darwin.go](../internal/vault/keychain_darwin.go)) | holds the vault key; cgo against Security.framework |

**How `Encrypted` works:**

- Secrets live in `~/Library/Application Support/keyward-vault/keyward.vault`
  (mode `600`). Each value is sealed separately with AES-256-GCM and bound to its
  name, so swapping entries in the file fails to decrypt.
- The only Keychain item is the 256-bit vault key (service `keyward-vault-key`).
  An upgrade therefore asks once, for the key, instead of once per secret. A real
  migration had 33.
- The key is read on the first request, not at startup, so a dialog never appears
  at login with nobody there. It then stays in the daemon's memory. Listing and
  deleting need no key, so they never ask.
- Secrets stored as Keychain items by older releases move into the vault on first
  use and are then deleted from the Keychain.

`Secret` ([secret.go](../internal/vault/secret.go)) wraps every value and redacts
itself through every `fmt` verb and through JSON, so a value can only leave by an
explicit `Bytes()` call. That keeps the leak surface small enough to audit.

## 6. Supporting pieces

| Package | What it does | Why it is shaped this way |
| --- | --- | --- |
| [internal/backup](../internal/backup/backup.go) | Encrypted backups of migrated originals, each with its own key in the vault | File permissions cannot keep out an agent running as you; `backups rm` deletes the key first |
| [internal/restore](../internal/restore/restore.go) | Writes values back into selected files | Reads no value until the user types `yes`; always single-quotes, so nothing is expanded |
| [internal/doctor](../internal/doctor/doctor.go) | Finds references with nothing behind them, and stored secrets nothing references | Never deletes: "unreferenced" is only proven when provenance names a scanned file |
| [internal/activity](../internal/activity/log.go) | `~/Library/Logs/keyward/activity.jsonl`: command, name, outcome, time | Fixed fields only; never values, argv, environment or error text |
| [internal/agents](../internal/agents/agents.go) | Writes `~/.agents/keyward.md`, instructions telling agents to use `keyward run` | No file is read by every agent, so keyward prints the line to add to each one's own instructions |
| [internal/launchd](../internal/launchd/launchd.go) | Per-user LaunchAgent for signed local installs | Starts only an installed daemon, never a development build |
| [internal/homebrew](../internal/homebrew) | Formula template and release tooling | Homebrew's install step is sandboxed from your home, so setup happens on first use |
| [cmd/keyward/main.go](../cmd/keyward/main.go) | Wires real dependencies into `internal/cli` | Everything else is injected, which is what makes the CLI testable |

## 7. What it protects, and what it does not

**Protects against:**

- an agent or tool reading `~/.zshrc`, `.env`, or the environment and finding a
  live credential;
- the same values reaching a transcript, a log, or a backup of your dotfiles.

**Does not protect against:**

- a process running as you that deliberately asks the daemon, or runs
  `keyward run -- env`;
- a command that is given a secret and then leaks it;
- anything with root, or with access to the daemon's memory.

The honest summary: keyward closes the accidental case, which is most of the real
risk on a developer machine, and says plainly that it does not close the
deliberate one.

## 8. How it is tested

- Test first throughout. All logic above the vault is tested against
  `vault.Memory`; `make verify` runs `go vet`, `gofmt`, and `go test -race`.
- The real Keychain is exercised by build-tagged integration tests
  (`make test-integration`) under a throwaway service name.
- Keychain dialogs cannot be detected after the fact: an approved dialog and no
  dialog look the same. Manual tests have the user click **Deny** and time the
  read; only a success in well under two seconds counts as "no dialog".
  [scripts/test-apple-dev-signing.sh](../scripts/test-apple-dev-signing.sh) shows
  the pattern.

## Questions engineers usually ask

**Why not just block agents from reading files?** That means wrapping every agent
you use, now and later. References work with any agent, because there is nothing
left in the file to find.

**Why a daemon instead of calling the Keychain from the CLI?** Keychain access is
tied to the exact binary. With unsigned builds, every rebuild or upgrade would
stop on dialogs. The daemon is the one stable caller.

**Why not one Keychain item per secret?** That was the first design. Each unsigned
upgrade then asked once per secret. One key in the Keychain makes it once per
upgrade. A Developer ID-signed release would remove even that.

**Can an agent still get a secret?** Yes, if it deliberately runs `keyward run`.
keyward removes the accidental exposure; it does not claim to stop a determined
process running as you.

**What if I uninstall?** `keyward uninstall` removes the daemon, logs, backups,
and package, and keeps the vault and its key. Run `keyward restore <file>` first
if you want plaintext values back in your files.

## Where to go next

- [design.md](design.md): every major decision and the alternative it beat.
- [obstacles.md](obstacles.md): what turned out hard or wrong, with measurements.
- [status.md](status.md): what is done, what is open, and what gates what.
