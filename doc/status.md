# Status

Last updated: 2026-10-02

## Where things stand

The tool works end to end on the real Keychain. `add`, `ls`, `rm`, `run`,
`migrate`, `restore`, `doctor`, `daemon`, and `service` are implemented. The daemon is the only
process that touches the Keychain, so CLI rebuilds never prompt. `make install`
builds and signs a local installation with a per-user login agent. Installed on this
Mac: the signed daemon is running and configured to start at login. Automated checks
and the isolated live installation test pass. `~/Applications/Keyward.app` provides
a **Keyward by Veilux** status window, activity-log access, and startup controls.

`make verify` runs `go vet`, `gofmt` and `go test -race`. `make test-integration`
also exercises the real Keychain, under a separate service name.

Signing: a daemon rebuilt with the same **Apple Development** certificate keeps
Keychain access, while self-signed and unsigned rebuilds do not (obstacles.md 2a).
Prebuilt signed distribution needs a Developer ID, which is untested. Source-built
Homebrew packaging is implemented without that requirement; publication is pending.

Direct access was also verified from a distinct signed command-line test binary:
read, replace, and delete of daemon-created dummy items all succeeded after their
creator process exited. Production still routes through the daemon. A signed CLI
can replace that architecture once cross-process coordination and logging are
handled; see [obstacles.md](obstacles.md) 2a.

### Known issues

- `Replace` succeeds across builds signed with the same Apple Development
  certificate. Replacement across unsigned builds remains untested (2a-bis).
- Login startup is configured; an actual logout/login has not been tested.
- The installed app and LaunchAgent are associated, but this Mac's existing
  Background App Activity entry still shows the personal signing-certificate name.
  Cached attribution may explain this; a fresh-machine notification is untested.
  Product branding does not change the certificate's publisher identity.
- Activity logging is best effort: storage failures warn in the CLI and operations
  continue. Same-user processes can read or modify it; tamper-evident audit history
  is not implemented. Idle files are cleaned on the next use.

## Component status

| Component | State | Notes |
| --- | --- | --- |
| `internal/handle` | **Done** | Parse, `Normalize`, format. Errors proven not to leak their input. |
| `vault.Secret` | **Done** | Redacts through every fmt verb and through JSON. Proven by test. |
| `vault.Store` | **Done** | Interface plus sentinel errors. The seam that keeps everything above it testable. |
| `vault.Memory` | **Done** | In-process fake, concurrency-safe, passes the contract suite under `-race`. |
| `vault/vaulttest` | **Done** | Contract suite. The real Keychain store will be held to exactly this. |
| Keychain store | **Done** | cgo against `SecItem*`. Passes the same contract suite as the fake, plus persistence and service-isolation tests. `make test-integration`. |
| `internal/resolve` | **Done** | Environment scanning, caching, all-or-nothing resolution, aggregate errors. 100% covered. |
| `internal/activity` | **Done** | Private JSONL metadata, 30 days / 50 MiB defaults, daily / 10 MiB rotation, cross-process locking, legacy log retention, configurable limits. |
| `internal/audit` | Not started | Tamper-evident history remains separate from activity logging. |
| `cmd/keyward` | **Done** | `add`, `ls`, `rm`, `run`. Logic in `internal/cli` with store, streams, environ, and exec injected. |
| `internal/migrate` | **Done** | Scan, detect, `Plan`, `Apply`. Dry run by default, redacted diff, backup, atomic write, idempotent. |
| `internal/restore` | **Done** | Separate explicit command; redacted plan for selected files, mandatory exact `yes`, metadata-only dry run, best-effort atomic private writes, retained Keychain entries. Uninstall warns users to restore first and requires confirmation before stopping startup. |
| `internal/mcpconfig` | Not started | Needs `run` to exist and work. |
| `keyward shell` | Not started | Independent of the above. |
| `internal/daemon` | **Done** | The only Keychain caller; the CLI is a client over a same-user Unix socket. CLI rebuilds never prompt; shutdown is bounded and availability can be checked without reading items. |
| `internal/launchd` | **Done** | Signed CLI installed in `~/.local/bin`; daemon running with login startup configured. Live tests passed for signed upgrade, item replacement, launchd restart, persistence, and uninstall. Rollback and path handling are covered by automated tests. |
| `internal/appbundle` | **Done** | Signed Keyward by Veilux status app installed in `~/Applications`. Native window verified. The app is registered with Launch Services and associated with the daemon; same-team checks and app rollback are covered by tests. |
| Code signing | Apple Development rebuild test passed twice | macOS 27.0.1: same-certificate rebuild reads without a prompt (0.06s, 0.04s); unsigned control denied in both runs. Developer ID distribution signing remains untested and requires the paid programme; free Personal Team signing cannot be used for distribution to others. See [obstacles.md](obstacles.md) 2a. Biometric entitlements remain untested. |
| `internal/doctor` | **Done** | Dangling, malformed, orphaned, unknown, plus stated coverage. Report-only. |
| Biometric gating | Not started | Feasibility unconfirmed — see [obstacles.md](obstacles.md). |

## What gates what

Not a schedule. A dependency order, so it is always clear what is actually
available to work on.

**Nothing gates these:**

- `internal/mcpconfig`: rewrite MCP server configs to launch via `keyward run`.
  Delivers the Finder-launch fix.
- `internal/audit`: tamper-evident history if required beyond local activity logs.
- Verify login startup at the next logout/login.
- Simplify signed local builds to direct Keychain access, with a cross-process
  lock and continued logging. The isolated access test has passed.

**Gated on public source and tap publication:**

- Source-built Homebrew installation; see [homebrew.md](homebrew.md). Local
  package verification, explicit publication approval, and GitHub authentication
  gate the public release.

**Gated on a paid Developer ID:**

- Signed, notarised prebuilt releases. Verify direct access and upgrades
  under Developer ID before using that architecture for distribution.

**Gated on the migration being lived with:**

Everything else. `shell`, grants, approval queue, MCP tool surface. Building
these before the core is in daily use would be building on a guess.

**Gated on the cgo vault being solid:**

- Biometric gating. It is the one genuine differentiator, and also the piece most
  likely to turn out infeasible. Attempting it early would risk the whole project
  on its hardest unknown.

## The decision point

**This is now runnable.** `keyward migrate ~/.zshrc` does the whole job in
one command, so the experiment costs a minute rather than an afternoon.

The project has one real go/no-go, and it is not about security:

> Migrate `~/.zshrc` and one project's `.env`, then work normally. If
> `keyward run --` is not close to invisible across `docker compose`, `phpunit`,
> and editor run configurations, stop.

Friction is the thing that kills tools like this, not weak guarantees. This test
runs as soon as `migrate` lands and needs no further machinery. If it fails, the
correct response is to stop building, not to push through.

## Changelog

**2026-10-02 (source-built Homebrew package)** — Added a formula template and
`cmd/keyward-release` to generate a committed source archive and matching checksum.
The Homebrew build delegates `service` commands to `brew services`, without a
certificate or companion app, and refuses a second daemon. Restore warnings and
confirmation remain in place. `make verify`, a real source install, `brew test`,
and formula style checks passed. The formula binary read its dummy item after
restart in 19.383ms. Service metadata verification identified Homebrew's changed
default job label; the formula and manager now use an explicit stable label,
`com.veilux-lab.keyward.homebrew`. Public tap/source publication requires
explicit approval and authenticated GitHub access; see [homebrew.md](homebrew.md).

**2026-10-02 (Veilux Lab repository)** — The owner transferred the project to
`veilux-lab/keyward`. Updated the local Git remote, Go module/import paths, signing
script, and repository documentation. Existing Apple signing, app, LaunchAgent,
and Keychain service identifiers remain stable for installed users. `make verify`
passed under the new module path.

**2026-10-02 (bounded activity logging)** — CLI and daemon events now share
`activity.jsonl`, with 30-day / 50 MiB defaults, daily / 10 MiB rotation, and
environment overrides. Cleanup runs on CLI startup and event writes; legacy
`daemon.log` counts toward the same budget without reading its contents. File
locks and checked directory descriptors protect concurrent writes and rotation.
Raw rejected names, values, arbitrary errors, provenance, environment, and child
arguments/output are excluded. `run` logs its exec attempt before replacement.
The status app opens the new log; LaunchAgent settings persist the selected limits.
`make verify` passed. A disposable unsigned CLI/daemon smoke test verified real
Keychain operations, secret redaction, rotation, expiry, the total budget including
legacy history, and private permissions. The owner's files and Keychain items
were untouched. The signed installation lifecycle test passed in 3.46s, including
prompt-free cross-build reads and replacement, restart, persistence, and uninstall.
The updated signed CLI and status app are installed, and the login daemon is
healthy. The installed log directory is mode `700`, files mode `600`, and the
LaunchAgent retains the default limits.

**2026-10-02 (direct signed access)** — Added a repeatable isolated test for a
signed command-line process accessing daemon-created items directly. It enforces
matching Apple signing requirements and distinct code hashes, stops the creator
daemon before direct access, compares values by hash, and cleans up its unique
service and files. Read took 23.523ms, replacement 11.839ms, replacement read
2.065ms, and deletion of replaced/untouched items 6.073ms/5.927ms. The test passed;
the unsigned build failed its signing preflight without touching items.
`make verify` passed. No production routing or real user secrets were changed.

**2026-10-02 (uninstall warning)** — Removed the combined `uninstall --restore`
option. Restoration is an explicit command. CLI uninstall warns users to run it
before removing Keyward, shows preview/restore examples, and waits for `yes` before
stopping the daemon. Refusal leaves startup intact. The native status window
also warns before disabling startup. Uninstall never reads or restores secrets.
Tests verify warning order, cancellation, and unchanged files/values. `make verify`
passed, and the Swift companion app compiled successfully.

**2026-10-02 (restore)** — Added `keyward restore [--dry-run] <file>...` and
`keyward service uninstall --restore <file>...`. The plan precedes mandatory exact
`yes` confirmation; there is no bypass flag. No values are fetched before approval.
Tests cover cancellation, redaction, safe shell quoting, dotenv limitations,
missing or denied items, file changes, symlinks, private modes, and uninstall
ordering. Restoration uses current references and current stored values, retains
Keychain entries, and does not recreate plaintext backups.
`make verify` passed. A disposable real-Keychain test exercised dry runs,
refusals, approved restoration, shell quoting, private file permissions, and
retained entries. Reading across signed builds took 0.030s. The updated signed
CLI and companion app are installed, and the login daemon is running. The owner's
real startup file and GitHub item were not restored or read during these checks.

**2026-10-01 (Veilux branding)** — Added the Keyward by Veilux status app, signed
alongside the CLI by `make sign` and installed by `make install`. Its native window
shows daemon health and offers log access and startup controls. The LaunchAgent
uses `AssociatedBundleIdentifiers`; installation verifies matching signing teams
and restores the previous app, binary, and agent on failure. The daemon identifier
remains unchanged. The isolated signed upgrade/replacement/restart/uninstall test
passed in 3.43s, with cross-build access under two seconds. The real installation
is running and the branded window was verified. This Mac's existing background
entry still displays the personal certificate name despite recording the app
association; fresh-machine attribution is untested. `make verify` passes.

**2026-10-01 (local installation)** — `make build`, `make sign`, `make install`, and
`keyward service install|status|uninstall`. Installation requires an Apple-signed
keyward binary, preserves spaces in paths, and restores the previous installation
if startup fails. The LaunchAgent uses an absolute binary path and a private log.
Health checks do not access the Keychain. A separate integration test covers signed
upgrades, replacement, launchd restart, and uninstall using a temporary job and dummy
item; it passed on macOS 27.0.1 in 3.22s. Cross-build reads and replacement each
succeeded in under two seconds. The real login agent is installed and responding.
An actual logout/login remains untested. `make verify` passes.

**2026-10-01 (daemon shutdown)** — SIGINT and SIGTERM give requests one second to
finish, then disconnect waiting clients so a Keychain dialog cannot prevent exit.
The instance lock is retained while requests drain. A write interrupted at shutdown
may have taken effect; the daemon logs that uncertainty. Regression tests cover a
blocked store, lock retention, client disconnection, and normal request completion.
`make verify` passes.

**2026-09-28 (migrate complete)** — `Plan`, `Apply`, and `keyward migrate`. Dry run
by default. The diff withholds values: printing the old line verbatim would spill
every secret in the file into scrollback and into the context of any agent that ran
the command, which is the leak the tool exists to prevent. Secrets are stored before
the file is touched, so a failure loses nothing. Verified by hand on a realistic rc
file: five values moved, five correctly left alone, mode preserved, backup intact,
second run a no-op, and `keyward run` resolving the result.

**2026-09-28 (migrate, part one)** — `internal/migrate` scanning and detection,
100% covered. Split from the writing half deliberately: this part only reads and
decides. The scanner is conservative by design — anything it cannot parse with
certainty is left untouched, because a missed secret is merely the status quo while
a mangled line breaks the user's shell.

**2026-09-28 (end of day)** — `cmd/keyward` and `internal/cli`: `add`, `ls`, `rm`,
`run`. The tool does something useful for the first time. `add` reads from stdin
only — a secret in argv is visible to `ps` and lands in shell history, which would
make keyward a worse place for a credential than the file it came from.
`golang.org/x/term` added as the only dependency, for disabling terminal echo.

**2026-09-28 (later still)** — `internal/resolve` implemented test-first and fully
covered. Resolution is all or nothing, because a partly resolved environment runs a
command with some values real and some still references — an authentication failure
with no visible cause, which is the confusion this tool exists to remove. Failures
are aggregated so a user sees every broken reference at once rather than one per
rerun.

**2026-09-28 (later)** — Keychain store implemented, passing the same contract
suite as the in-memory fake. The CoreFoundation plumbing sits in C rather than Go
because cgo maps the CF types inconsistently on macOS. Two findings recorded in
[obstacles.md](obstacles.md): the legacy keychain races under concurrent
enumeration (fixed in-process with a mutex, still open across processes), and the
data protection keychain needs a signing entitlement, which makes biometric gating
a larger job than assumed.

**2026-09-28** — `vault.Secret`, `vault.Store`, and `vault.Memory` implemented
test-first, plus the `vaulttest` contract suite that the real Keychain store will
also have to pass. `handle.Normalize` extracted so the vault and the reference
parser share one definition of a valid name. MIT licensed. `make verify` added.

**2026-09-27** — Repository created. `internal/handle` implemented test-first.
Design, mission, obstacles, and landscape documented. Scope narrowed from a
general secrets broker to the shell-rc problem specifically.
