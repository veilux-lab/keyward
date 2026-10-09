# Status

Last updated: 2026-10-09

## Where things stand

The tool works end to end on the real Keychain. `add`, `ls`, `rm`, `run`,
`migrate`, `restore`, `backups`, `agents`, `doctor`, `daemon`, `service`,
`uninstall`, and `version` are implemented. The daemon is the only
process that touches the Keychain, so CLI rebuilds never prompt. `make install`
builds and signs the CLI with a per-user login agent. The project no longer builds
a companion app. Use `keyward service status`, `install`, and `uninstall` for
startup controls, and `~/Library/Logs/keyward/activity.jsonl` for activity.
Installed on this Mac: the signed daemon is running and configured to start at
login. The owner's previously installed app and live daemon have been left
untouched; the app is unnecessary for CLI startup. The CLI-only signed lifecycle
test passed in 3.54s, including upgrades, prompt-free reads and replacement,
restart, persistence, and uninstall under an isolated service.

`make verify` runs `go vet`, `gofmt`, `go test -race`, and Python release tests.
It requires Python 3 alongside Go and Apple's command line tools. `make test-integration`
also exercises the real Keychain, under a separate service name.

Signing: a daemon rebuilt with the same **Apple Development** certificate keeps
Keychain access, while self-signed and unsigned rebuilds do not (obstacles.md 2a).
Prebuilt signed distribution needs a Developer ID, which is untested. Source-built
Homebrew releases use `veilux-lab/keyward` for the formula, source archive, and
service commands, without that requirement. The repository is public. The owner
deleted the original `v0.1.0` tap on October 4; its repository and release assets
were backed up under ignored `bin/retired-homebrew-tap`. Existing old installations
can switch using their local tap checkout.

Public release
[`v0.1.11`](https://github.com/veilux-lab/keyward/releases/tag/v0.1.11), published
2026-10-08, is the current formula, with a prebuilt Apple Silicon bottle.
`v0.1.3` added first-use daemon startup, the optional
`brew keyward-install --start-daemon` installer, and CLI-only local installation.
Checks and commands without vault calls leave the daemon stopped; explicit service
uninstall disables first-use startup until service install re-enables it. Custom
sockets and service names remain manual. `v0.1.2` was never published. `v0.1.1`
still requires explicit service startup.

The free [release workflow](releases.md) published `v0.1.3` from `8940863` in
[CI run 37361912182](https://github.com/veilux-lab/keyward/actions/runs/37361912182):
native ARM and Intel verification, `brew test` on the exact archive, publication,
and the bot's formula update (`db15932`). Pushes that change only Markdown or
`doc/` no longer release; `v0.1.4` came from the push that added that rule. Developer ID-signed, notarized downloads
stay optional behind `KEYWARD_SIGNED_RELEASES=true`; an end-to-end signed CI
release remains untested.

Releases include a prebuilt Apple Silicon bottle: CI builds it, pours it through
the formula, merges it into the release formula, and refuses to publish without it.
Installing from a bottle needs no Go. The bottle embeds `/opt/homebrew`, so custom
prefixes still build from source. On Intel, Homebrew 7 has no Go bottle (Tier 3),
so the formula cannot build there, and Intel Homebrew installation is unsupported
until Go is built from source.

First install on a second Mac (macOS 27.0, Homebrew 7.0.7, no earlier Keyward)
is in progress. `brew tap` printed two "not trusted" warnings and skipped the
formula. `brew install veilux-lab/keyward/keyward` printed the same warnings,
trusted only the Keyward formula, and installed `0.1.4`. It also upgraded the
user's Homebrew Go from 1.26.4 to 1.27.1 as a build dependency, and Homebrew's
generic caveat suggests `brew services start` beside Keyward's own
`keyward service install`. Keychain prompts, the background-item notice, and
login startup are not yet observed.

Direct access was also verified from a distinct signed command-line test binary:
read, replace, and delete of daemon-created dummy items all succeeded after their
creator process exited. Production still routes through the daemon. A signed CLI
can replace that architecture once cross-process coordination and logging are
handled; see [obstacles.md](obstacles.md) 2a.

### Known issues

- `Replace` succeeds across builds signed with the same Apple Development
  certificate. Replacement across unsigned builds remains untested (2a-bis).
- Login startup is configured; an actual logout/login has not been tested.
- This Mac's Background App Activity entry shows the personal
  signing-certificate name. Fresh-machine notifications remain untested, and
  removing the app from the project does not change the signing publisher identity.
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
| `vault/vaulttest` | **Done** | Contract suite. The real Keychain store is held to exactly this. |
| Keychain store | **Done** | cgo against `SecItem*`. Passes the same contract suite as the fake, plus persistence and service-isolation tests. `make test-integration`. |
| `internal/resolve` | **Done** | Environment scanning, caching, all-or-nothing resolution, aggregate errors. 100% covered. |
| `internal/activity` | **Done** | Private JSONL metadata, 30 days / 50 MiB defaults, daily / 10 MiB rotation, cross-process locking, legacy log retention, configurable limits. |
| `internal/audit` | Not started | Tamper-evident history remains separate from activity logging. |
| `cmd/keyward` | **Done** | Every command. Logic in `internal/cli` with store, streams, environ, and exec injected. |
| `internal/migrate` | **Done** | Scan, detect, `Plan`, `Apply`. Redacted plan, then an exact `yes`; `--dry-run` previews. Encrypted backup, atomic write, idempotent. |
| `internal/backup` | **Done** | AES-256-GCM backups with a per-backup key in the vault; `recover` and `rm`, which deletes the key first. |
| `internal/agents` | **Done** | Writes `~/.agents/keyward.md` at setup; migrate, doctor, and uninstall say how to link or unlink agents. |
| `internal/restore` | **Done** | Separate explicit command; redacted plan for selected files, mandatory exact `yes`, metadata-only dry run, best-effort atomic private writes, retained Keychain entries. Uninstall warns users to restore first and requires confirmation before stopping startup. |
| `internal/mcpconfig` | Not started | Nothing gates it. |
| `keyward shell` | Not started | Independent of the above. |
| `internal/daemon` | **Done** | The only Keychain caller; the CLI is a client over a same-user Unix socket. CLI rebuilds never prompt; shutdown is bounded and availability can be checked without reading items. First-use managed startup shipped in `v0.1.3`; requests are not replayed. |
| `internal/launchd` | **Done** | Signed CLI installed in `~/.local/bin`; daemon running with login startup configured. The isolated CLI-only lifecycle test passed in 3.54s for signed upgrade, reads and replacement, launchd restart, persistence, and uninstall. First-use startup and persistent explicit disabling shipped in `v0.1.3`. |
| Code signing | Apple Development rebuild test passed twice | macOS 27.0.1: same-certificate rebuild reads without a prompt (0.06s, 0.04s); unsigned control denied in both runs. Free Apple Development signing supports local use; Developer ID signing and notarization require paid membership and remain untested. Homebrew source distribution needs neither. See [obstacles.md](obstacles.md) 2a. Biometric entitlements remain untested. |
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

**Gated on a fresh Mac:**

- First-user Keychain prompts and login startup for the public source-built
  Homebrew package; see [homebrew.md](homebrew.md). In progress on a second Mac;
  installation itself succeeded. Repeat with the first bottled release.

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

**2026-10-09 (agent instructions)** — keyward writes `~/.agents/keyward.md` when
the daemon first starts or restarts after an upgrade, and on `service install`,
because Homebrew's install step cannot write to the home directory. Migrate then
prints the line to add to each installed agent's global instructions, since no
single file is read by every agent. Fixed text, so it never needs a user's variable
names; agents find references with `grep 'cap://'`. `keyward agents` does both on
demand, `doctor` reminds while an agent is not pointed at it, and `uninstall`
removes the file. A file keyward did not write is never replaced or removed.

**2026-10-09 (encrypted backups)** — Migrate backups are encrypted with a per-backup
AES-256-GCM key held in the vault, because `0600` does not keep out an agent running
as the same user. `keyward backups rm` deletes the key first, `keyward backups
recover <file>` writes the original beside the file after a "yes", and `ls` and
`doctor` leave the keys out. Plaintext backups from earlier releases are still
listed, marked as plaintext. Verified on the real Keychain under a throwaway service.

**2026-10-08 (password names, keyward run guidance)** — Names with the whole words
`PW`, `PWD`, `PASS`, or `PASSPHRASE` now count as credentials; `BYPASS_…` and
`PASSENGER_…` do not. A real `~/.zshrc` dry run had left `ACCOUNTS_DB_PW` and
`DEV_DB_PASS` alone. The dry run, confirmation, and result now say that programs
need `keyward run --` after migration, including editors. A blank line seen in
that dry run was not in Keyward's output.

**2026-10-08 (restart after upgrade)** — `brew upgrade` left the old daemon
running; with its files replaced, a Keychain read failed with OSStatus 100002.
The daemon now reports its version on ping, and the CLI checks it once before its
first vault request. A different version is restarted through `brew services
restart` or `launchctl kickstart -k`, then checked again; development builds skip
the check. Without a managed restart, the error names `keyward service install`.

**2026-10-06 (uninstall and caveats, prepared)** — `keyward uninstall` asks for `yes`,
stops the daemon, deletes local state, backups, and default logs, then removes the
Homebrew formula and tap or the signed CLI. Keychain items are kept. A plain
`brew uninstall` cannot do this: formulas have no uninstall hook. Formula caveats
are cut to six lines; Homebrew's own `brew services` lines cannot be suppressed
for a formula with a service. Local until an approved push.

**2026-10-06 (backups, stop, options, colour, prepared)** — Migrate backups move to a
private `~/Library/Application Support/keyward/backups` (mode `600`) instead of
beside the original, which copied the original's mode. `keyward backups` lists them,
`keyward backups rm <file>...|--all` removes them, a restore without skips removes
that file's backups (including older siblings), and `doctor` reminds while any
remain. `keyward service stop` unloads the daemon and blocks first-use startup until
`service start` or the next daemon start, such as at login; Homebrew's login
registration is kept. Service messages are rewritten in plain language. Options
may follow arguments or precede the command, except before `run`. Output is
coloured only on terminals, honouring `NO_COLOR`. Tests came first.
Local until an approved push.

**2026-10-05 (Homebrew bottles, prepared)** — The release workflow builds the
source archive once, then builds and pours an Apple Silicon bottle before
publishing. `scripts/merge-homebrew-bottles.sh` checks the bottle's release, root
URL, and checksum before Homebrew writes the formula's bottle block; release
metadata and publication require it. The first CI run failed safely; the fix
re-trusts the formula after uninstalling and drops the Intel bottle. Tests came
first and cover refusal outside CI, re-trust after uninstall, mismatched archives
or bottles, a wrong or extra architecture, another release's bottles, and an
existing tap. Manual releases remain source-only.

**2026-10-05 (first install on a second Mac)** — Installed public `v0.1.4` through
the documented tap and formula commands. Recorded the trust warnings, the Go
build-dependency upgrade, and Homebrew's `brew services` caveat. Prebuilt bottles
would remove the Go and command line tools requirement for matching Macs.

**2026-10-05 (v0.1.3 published)** — The free-default release change was pushed to
`main`. CI run 37361912182 verified and published `v0.1.3`, then updated the
formula. It is the first public release with first-use daemon startup. Run numbering
skipped `v0.1.2`, whose earlier run stopped at the old token check. Updated the
README and setup docs to match.

**2026-10-05 (free automatic releases, prepared)** — Source/Homebrew publication
is now the default, using `GITHUB_TOKEN`. No Apple credentials or paid membership
are needed. Developer ID signing runs only when `KEYWARD_SIGNED_RELEASES=true`;
enabling it still requires all signing credentials and successful notarization.
An optional publication token handles older queued commits when GitHub requires
workflow permission. Release manifests record the selected type and exact asset
list. Draft retries and published reruns refuse mismatched provenance or mixed
source/signed assets; resumed drafts refresh their notes. The default source path,
signed failures, and retry guards have regression coverage. This change is local
until an approved push.

**2026-10-05 (automatic releases, prepared)** — Added a main-only GitHub Actions
workflow with native ARM/Intel verification, a universal CLI build, Developer ID
signing, notarization, and a stapled disk image. Each run uses version
`0.1.(run number + 1)`; queued publishers retain pending pushes. Source archives,
checksums, and provenance accompany the signed CLI. Draft uploads can resume;
published assets are retained and tags must match the tested source commit.
The Homebrew bot updates only the formula after publication, verifies before
each commit, retries ordinary fast-forward races, and refuses version downgrades
or changed checksums at the same version. Signing credentials stay in environment
variables and private temporary files, with cleanup on exit. The owner's keys
were not exported. Failure/rerun/concurrent-update tests and shell checks pass.
Workflow validation passes apart from actionlint 1.7.12's lack of support for
GitHub's documented `queue: max` property, which was checked separately. Actual
Developer ID signing and notarization still require the secrets described
in `doc/releases.md`, an approved push, and a successful first CI run.
The owner approved pushing the four pending commits to `main`. GitHub now points
to `0c594dd`; both native CI build jobs passed. The publisher stopped at its
missing-token configuration check before any signing or release mutation.

**2026-10-05 (CLI-only installation, prepared)** — Removed the companion app,
Swift build, bundle generation, Launch Services registration, and app association
from the project. Signed installation now contains the CLI and a per-user
LaunchAgent. Startup controls remain `keyward service status|install|uninstall`;
activity is in `~/Library/Logs/keyward/activity.jsonl`. The owner's existing app,
daemon, and Keychain items were left untouched. `make verify`, integration-test
compilation, and CLI-only sign/install dry runs passed. The isolated
`TestSignedInstallLifecycle` passed in 3.54s: distinct CLI builds signed with the
same Apple Development certificate read and replaced dummy items in under two
seconds, then verified restart, persistence, and uninstall. The initial `v0.1.2`
candidate from `f724883` is superseded. The replacement from `5929237` has SHA-256
`2f2c5541f465676b2e3eea6ea771cad5cb12b66edac09a8b167a4cf3a203f90d`.
Its real source installation, `brew test`, formula style, service metadata, and
absence of Swift/app-bundle components passed; the fixture was removed. It is
retained under ignored `bin/homebrew-0.1.2-cli` as packaging evidence. CI will
generate its own archive from the triggering commit, including the workflow.

**2026-10-04 (first-use daemon startup, prepared)** — Managed vault clients start
an absent daemon before sending a request. Homebrew enables its service; signed
local installations bootstrap an existing LaunchAgent. Health checks and commands
without vault calls stay passive. Custom sockets and services remain manual.
Service uninstall saves a private disabled marker; explicit service install
re-enables startup. Added the optional `brew keyward-install --start-daemon`
installer command, which finishes Homebrew installation before starting the
daemon. Normal formula installation leaves startup for first use; signed
`make install` still starts immediately. Test-first cases cover startup before
vault requests, no replay after a sent write, concurrent startup, private state,
explicit disabling, installed signed configuration, and isolated namespaces.
`make verify` passes, including race checks. The first `run` resolved a dummy
reference through an automatically started Memory-vault daemon. Installer tests
use fake executables; shell syntax and Homebrew command discovery also pass.
No live services or Keychain items were accessed. Prepared `v0.1.2` from source
commit `f724883`; archive SHA-256 is
`8e83d1a73f0b3561743654734357ef2ac8c0a89f9127a4c7c4f89f9c8be351d7`.
A renamed, unlinked Homebrew fixture built from that exact archive and passed
`brew test`. The production formula passed style and service metadata checks;
fixture packages, tap, trust entries, cache, and logs were removed. The installed
owner daemon and Keychain items were not changed. This initial archive is
superseded by the CLI-only update and will not be published.

**2026-10-04 (retired original tap)** — The owner deleted
`veilux-lab/homebrew-tap` after the formula, source archive, and service routing
moved to `veilux-lab/keyward`. The original repository and release assets were
backed up under ignored `bin/retired-homebrew-tap`. Existing old installations
retain their binaries and Keychain items; migration uses the local old tap to stop
the service before removing it. New old-tap clones and uncached downloads no
longer work.

**2026-10-03 (one repository for Homebrew)** — Updated source release URLs,
formula homepage, and service commands to use `veilux-lab/keyward`. Added
`Formula/keyward.rb` so the repository serves as its own tap through an explicit
clone URL. Prepared `v0.1.1` from cleaned source commit `94a601d`; archive SHA-256
is `a8a3b95e941541d29565b5cca44ba157ef4a9db5203018c8a9c9ecc2cfb0241a`. Shortened
the README to installation and everyday use; detailed setup is in `doc/install.md`
and `doc/homebrew.md`. Disabled Claude commit/PR attribution in project settings
and agent instructions. Removed 28 Claude co-author trailers from local history,
preserving all commit trees, identities, timestamps, topology, and remaining
message text. The rewritten commits no longer carry their invalidated signatures;
the original history and commit map are retained under ignored `bin/history`.
Tests first failed against the old release URL and service name, then passed with
the new targets; `make verify` passed. A disposable Homebrew source install,
`brew test`, formula style, and service metadata checks passed. Its dummy item
was read after a same-binary daemon restart in 12.423ms, then deleted; the fixture
package and tap were removed. The owner made the repository public and approved
publishing the rewritten `main` and release `v0.1.1` there. The existing `v0.1.0`
tap is only needed while switching installations.

**2026-10-02 (public Homebrew release)** — Published the approved public
`veilux-lab/homebrew-tap` repository and release `v0.1.0`, including the tested
source archive from commit `821d4dd`. The primary repository remains private.
The public download matches SHA-256
`80fcac2040f3a841a70b6d75df3f7276e2790680145cdbf8729c76e9a2493464`.
Verified installation from the public release and the fully qualified command
`brew install veilux-lab/tap/keyward`, which handles formula-specific trust on
Homebrew 7. Updated setup instructions to use that command. The signed owner
installation was retained; first-user prompts and login startup on a fresh Mac
remain untested.

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
The final formula was reinstalled successfully. A real `brew services` fixture
verified startup, automatic restart, and dummy resolution in 0.122s/0.086s, then
removed its startup configuration and Keychain item. The installed Homebrew CLI
also refused to start over the owner's signed agent. The owner installation was
not replaced, and real secrets and startup files were not accessed.

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
