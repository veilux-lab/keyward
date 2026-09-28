# Obstacles and complexities

Honest list. Anything here that turns out to be worse than described should
change the design, not get argued away.

## 1. Native credential hooks do not stop a deliberate agent

**Severity: high. Already invalidated an earlier design.**

An early plan was to delete `~/.aws/credentials` and replace it with
`credential_process` in `~/.aws/config`, on the reasoning that there would then
be nothing to read. That reasoning is wrong.

`aws configure export-credentials --format env` prints plaintext credentials to
stdout, resolves through the `credential_process` chain, and has no documented
way to be disabled or restricted. `git credential fill` is equivalent. AWS's own
documentation warns that `credential_process` "could be a security risk if the
command to generate the credentials becomes accessible by non-approved processes
or users" — which describes an agent exactly.

The generalisation: **every native credential hook is designed to be invoked by
tooling, and an agent that can run shell commands is tooling.** Migration does
not remove the secret; it converts a file read into a command execution, and the
agent can do both.

Consequences:

- The invariant is scoped to "no plaintext on disk, never in agent context" — not
  "agents cannot obtain credentials."
- The accidental case is genuinely closed. The deliberate case is not, and
  [mission.md](mission.md) says so.
- Closing the deliberate case needs some notion of *which actor is asking*, which
  is the one thing a wrapper-free design cannot easily know.

Also practical: the AWS CLI does not cache `credential_process` output, so the
broker must implement caching or be invoked on every single API call.

## 2. Biometric gating may not be reachable

**Severity: medium. Blocks the only real differentiator.**

macOS Keychain items can in principle be gated on user presence, which would put
Touch ID in front of every resolution — a hardware-backed human in the loop that
a shell-capable agent physically cannot satisfy. That would close obstacle 1
without any wrapper, and nothing in the landscape does it.

Unconfirmed:

- Apple's documentation for the relevant access-control flag was not reachable
  during research; behaviour for a non-GUI CLI process is unverified.
- `keybase/go-keychain` is cgo-based and maintained but exposes no
  `SecAccessControlCreateWithFlags` support, so this needs a custom cgo bridge.
- A GitHub search for a Go Touch ID binding returns nothing. No prior art to
  lean on.
- Prompting on every resolution would be intolerable, so it needs caching with a
  TTL — which is the time-boxed grant mechanism, arriving through the back door.

Treat as research, not a planned feature, until a spike proves a CLI process can
trigger and satisfy the prompt.

## 2b. The legacy Keychain races under concurrent enumeration

**Severity: low intra-process (fixed), open across processes.**

Found by running the contract suite's concurrency case against the real Keychain:
`SecItemCopyMatching` with `kSecMatchLimitAll` returns OSStatus **-67701**
(`errSecInvalidRecord`) when another thread adds or deletes an item mid-walk. The
legacy file-based keychain is not safe for concurrent enumeration and mutation.

Fixed for one process by a package-scoped mutex serialising every `SecItem` call.
The lock is package scoped rather than per-store deliberately: the keychain file is
a single shared resource, so two `Keychain` values in one process would otherwise
still collide.

**Residual:** nothing orders operations *between* processes. Two keyward processes
listing and mutating simultaneously can still hit this. Rare in the intended usage
— one interactive command at a time — but it is a real hole, and the fix if it ever
bites is a file lock or a single long-lived daemon owning all Keychain access.

Worth noting this is the kind of defect only an integration test finds. Every unit
test passed while it was present.

## 2c. The data protection keychain needs an entitlement

**Severity: medium. Constrains the biometric plan.**

keyward uses the default file-based keychain. The modern data protection keychain
(`kSecUseDataProtectionKeychain`) is where access-control flags including biometry
live, but it requires the calling binary to be signed with a keychain-access-group
entitlement. An unsigned Go binary should expect OSStatus -34018
(`errSecMissingEntitlement`), which is mapped to `ErrDenied` for exactly this
reason.

So biometric gating probably means code signing and provisioning, not just a few
extra lines of cgo. That is a materially larger undertaking than obstacle 2
implied, and another reason to leave it until last.

## 2d. Orphaned vault entries accumulate

**Severity: low. Hygiene, not exposure.**

Deleting a migrated line from an rc file leaves its secret in the Keychain,
referenced by nothing. `keyward migrate` has no view of what the vault contains
beyond the file in front of it, so it cannot notice.

Not a leak — the value is exactly where it should be. But `keyward ls` grows over
time, and an orphan becomes a conflict if the same variable is later re-added with a
different value. `Plan.Check` now demotes that conflict to a skip and names
`keyward rm` as the fix, so it is visible and recoverable rather than a failure
after approval.

The proper answer is a reconciliation command — `keyward doctor`, or `ls --orphaned`
— that compares vault entries against the references found in known config files.
Not built.

## 3. Migration friction is the real project risk

**Severity: high. This is the go/no-go.**

Once `~/.zshrc` holds references, everything that reads those variables breaks
until it goes through `keyward run`: `docker compose`, test runners, editor run
configurations, anything launched from a GUI. Each is a small tax, and the sum
decides whether the tool stays installed.

There is no clever fix. The mitigation is to measure it early — see the decision
point in [status.md](status.md) — and to accept a negative answer.

## 4. cgo resists test-driven development

**Severity: low. Solved, but needs discipline.**

The Keychain layer cannot be unit tested meaningfully: it touches real OS state,
may prompt, and pollutes the developer's own Keychain.

Approach: `vault.Store` as an interface, all logic tested against an in-memory
fake, the cgo implementation kept thin enough to be nearly declarative, and one
build-tagged integration test excluded from `make test`.

The discipline part is resisting the urge to put logic in the cgo layer because
it is convenient. Anything untested there is untested forever.

## 5. Go cannot reliably zero a secret in memory

**Severity: low, but do not overclaim it.**

Buffers can be zeroed, but Go's garbage collector copies and moves values, so a
secret may persist in memory the program no longer references. `keyward` should
not claim values are unrecoverable from process memory. The README states this
rather than implying stronger protection than exists.

Related: never write a value to stderr. AWS documents that SDKs capture and log
stderr, and the same applies to anything wrapping keyward.

## 6. MCP config rewriting is fragile

**Severity: medium.**

Rewriting another tool's configuration file means owning a format that tool can
change without warning. Config locations differ per agent, may be JSON with
comments, and may be rewritten by the agent itself — silently discarding the
changes.

Mitigations: never rewrite without a backup, make the rewrite idempotent and
detectable so it can be re-applied after being clobbered, and provide a
`keyward doctor` that reports whether each config is still wired correctly.

## 7. A secret can still leave through a sanctioned path

**Severity: accepted.**

An approved command runs, its output contains credential material, and that
output goes back to the agent. keyward cannot distinguish this from legitimate
use.

Not solvable at this layer. Scanning capability output is possible later; an
egress-control tool covers it properly. Worth interoperating with such a tool
rather than reimplementing one.

## 8. The reference format is a one-way door

**Severity: low, but decide deliberately.**

Once references are committed to config files and written into Keychain item
names, changing the format means migrating every file and item. `cap://` is
chosen for parser-safety, but it is a prefix that will be hard to revise later.

Deliberately deferred: namespacing (`cap://project/name`). The parser currently
rejects slashes, which keeps the door open without committing to a scheme.
