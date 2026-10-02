# Status

Last updated: 2026-10-01

## Where things stand

The tool works end to end on the real Keychain. `add`, `ls`, `rm`, `run`,
`migrate`, `doctor` and `daemon` are implemented. The daemon is the only process
that touches the Keychain, so CLI rebuilds never prompt. Not yet packaged: build
with `go build ./cmd/keyward`.

`make verify` runs `go vet`, `gofmt` and `go test -race`. `make test-integration`
also exercises the real Keychain, under a separate service name.

Signing: a daemon rebuilt with the same **Apple Development** certificate keeps
Keychain access, while self-signed and unsigned rebuilds do not (obstacles.md 2a).
Shipping to other people needs a Developer ID, which is untested.

### Known issues

- **`Replace` (`add -force`) is untested across builds.** It uses `SecItemUpdate`,
  which may refuse items another build created, as `SecItemDelete` did (2a-bis).
- The daemon is started by hand; there is no launchd agent.

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
| `internal/audit` | Not started | Independent; can land any time. |
| `cmd/keyward` | **Done** | `add`, `ls`, `rm`, `run`. Logic in `internal/cli` with store, streams, environ, and exec injected. |
| `internal/migrate` | **Done** | Scan, detect, `Plan`, `Apply`. Dry run by default, redacted diff, backup, atomic write, idempotent. |
| `internal/mcpconfig` | Not started | Needs `run` to exist and work. |
| `keyward shell` | Not started | Independent of the above. |
| `internal/daemon` | **Done** | The only Keychain caller; the CLI is a client over a same-user Unix socket, so CLI rebuilds no longer prompt. Verified end to end across two builds. Not yet started at login (launchd). |
| Code signing | Apple Development rebuild test passed twice | macOS 27.0.1: same-certificate rebuild reads without a prompt (0.06s, 0.04s); unsigned control denied in both runs. Developer ID distribution signing remains untested and requires the paid programme; free Personal Team signing cannot be used for distribution to others. See [obstacles.md](obstacles.md) 2a. Biometric entitlements remain untested. |
| `internal/doctor` | **Done** | Dangling, malformed, orphaned, unknown, plus stated coverage. Report-only. |
| Biometric gating | Not started | Feasibility unconfirmed — see [obstacles.md](obstacles.md). |

## What gates what

Not a schedule. A dependency order, so it is always clear what is actually
available to work on.

**Nothing gates these:**

- Test `Replace` across builds.
- `internal/mcpconfig`: rewrite MCP server configs to launch via `keyward run`.
  Delivers the Finder-launch fix.
- `internal/audit`: append-only JSONL.
- A launchd agent for the daemon.
- Signed builds on the personal Mac, with the Apple Development certificate.

**Gated on a paid Developer ID:**

- Signed, notarised releases and a Homebrew tap. Then decide whether the daemon is
  still needed once releases keep Keychain access across upgrades.

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
