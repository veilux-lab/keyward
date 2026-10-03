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

**Severity: low. Fixed within a process; across processes, closed by the daemon.**

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

The daemon is now that fix. It is the only Keychain caller, a lock file limits it to
one instance, and the mutex orders its concurrent requests.

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

## 2a. An unsigned binary loses Keychain access when rebuilt — worked around

**Severity: was blocking. Worked around by the daemon (option 3 below); signing
would still be the proper fix.**

### Resolution

`keyward daemon` is the only process that touches the Keychain. The other commands
are clients over a same-user Unix socket. Measured end to end: one CLI build
migrated a real rc file's 32 secrets, and a second, different build resolved all 32
through `keyward run` with no prompt. Each resolved value was identical to the
original, compared by hash.

What remains:

- Rebuilding the **daemon** hits the original problem. Measured: restarting the same
  daemon binary reads its items with no prompt. A rebuilt daemon lists names without
  a prompt, but each read blocks on a dialog, once per item. A self-signed
  certificate does not avoid it on macOS 27 (below). Apple Development signing
  with the same certificate does (tested below), which supports trying Developer
  ID signing for prompt-free daemon upgrades; Developer ID itself remains untested.
  A free Personal Team certificate cannot be used to distribute the daemon to
  other people; that requires Developer ID and the paid Apple Developer Programme.
- The daemon must be running. Without it, commands fail at once with a message
  saying how to start it, so they never hang.
- The ACL no longer separates keyward from other processes the user runs. See
  [design.md](design.md), "One process touches the Keychain".

### Self-signed signing, retested (2026-10-01)

On macOS 27 (this laptop), a rebuild signed with the same self-signed certificate
still prompts. The dialog read `kw-b wants to access key "keyward-retest" in your
keychain`; denying it failed the read. An earlier laptop run that appeared to pass
did not tell an approved dialog from no dialog, so it proved nothing.

On a CI runner (macOS 26, a fresh keychain, nobody to approve), the same test
passed: signed rebuilds read without a prompt, trusted certificate or not, while an
unsigned rebuild blocked. Whether macOS 27 is stricter or the fresh keychain behaves
differently is unknown.

Signing also brings its own dialog the first time: `codesign wants to access key
"..." in your keychain`, once per signing until "Always Allow" is chosen.

### Apple Development signing, tested (2026-10-01)

On macOS 27.0.1 (26A434), two distinct builds signed with the same Apple Development
certificate read the dummy item without a prompt. Both had the same 10-character
team ID; the unsigned control had no team ID. Their designated requirement named
`com.nwokolo24.keyward`, Apple's generic trust anchor, and the signing certificate's
common name.

| Build | Result in both runs | First valid run | Repeat run |
| --- | --- | --- | --- |
| `kwd-a` (item creator) | READ | 0.04s | 0.03s |
| `kwd-b` (signed rebuild) | READ | 0.06s | 0.04s |
| `kwd-unsigned` (unsigned rebuild) | BLOCKED, access denied | 24.52s | 74.39s |

The unsigned control reported `prompt dismissed: access to the secret was denied`.
Its timing includes the owner's time to answer the dialog. On the repeat, the
owner confirmed Deny on `kwd-unsigned` and no `kwd-b` dialog. The item-access dialog
contained `your confidential information stored in`; complete wording was not
captured. A codesign dialog requested access to the Apple Development signing key.

**Pass:** the signed rebuild read in under two seconds while the unsigned control
was denied. Apple Development signing survives a rebuild on this Mac. This supports
testing Developer ID for distribution, without proving that certificate renewal or
a change of team preserves access.

### Direct signed access to daemon-created items, tested (2026-10-02)

A command-line integration-test binary called `vault.NewKeychainService` directly
on macOS 27.0.1 (26A434). The installed daemon binary created two dummy items under
a unique test service in a disposable process. That process exited and its socket
was removed before the direct calls. The caller and daemon had different code
hashes, the same Apple Development signing team and identifier, and identical
designated requirements.

| Direct operation | Result | Duration |
| --- | --- | --- |
| Read daemon-created item | Value matched by SHA-256 | 23.523ms |
| Replace daemon-created item | Success | 11.839ms |
| Read replacement | Value matched by SHA-256 | 2.065ms |
| Delete replaced item | Success; subsequent read reported not found | 6.073ms |
| Delete untouched daemon-created item | Success; subsequent read reported not found | 5.927ms |

All calls succeeded well below two seconds. The test service was empty afterward;
the temporary daemon and files were removed. No real user items were read. The
unsigned test build was rejected by the signing preflight before creating items;
this run did not repeat the unsigned item-access control from the earlier test.

This verifies direct access with the same certificate and identifier on this Mac.
The daemon is no longer required to solve that access problem. Production still
uses it; removing it would also require coordination between CLI processes and
preserving activity logging. Certificate renewal and team changes remain untested.

To repeat, compile and sign the test caller with the installed daemon's identity:

```sh
go test -c -tags integration -o bin/keyward-direct-test ./internal/vault
codesign --force --sign "$SIGN_IDENTITY" --identifier com.nwokolo24.keyward bin/keyward-direct-test
KEYWARD_TEST_DAEMON_BINARY="$HOME/.local/bin/keyward" bin/keyward-direct-test -test.run '^TestSignedDirectAccessToDaemonItems$' -test.v -test.timeout 90s
```

Allow codesign's signing-key prompt, but Deny any item-access prompt during the
test. A slow successful call is inconclusive, not a prompt-free pass.

### The mechanism

A Keychain item carries an access control list: which programs may read its value.
A program not on the list triggers the familiar "X wants to use your confidential
information stored in Y" dialog.

The list does not store a filename. It stores a *code requirement*. For a
code-signed program that requirement derives from the signing identity, which is
stable across rebuilds — this is why a password manager can update itself and still
read your vault. For an **unsigned** program there is no identity to point at, so
the requirement pins the binary itself. `go build` produces a different binary every
time, so every build of keyward is a program the Keychain has never seen.

### Measured

| Case | Result |
| --- | --- |
| Same binary reads its own item | instant |
| Rebuilt binary reads the same item | **blocks on a GUI dialog** (exit 124, SecurityAgent running) |
| `/usr/bin/security` reads a keyward item | blocked |
| `/usr/bin/security` deletes someone else's item | **succeeds, no authorisation** |

### Why blocking rather than annoying

The flagship use case launches MCP servers through `keyward run`. After any upgrade
that would hang on a dialog the user may never see, with the editor waiting on it.
A tool that intermittently blocks on an invisible prompt is worse than the problem
it solves.

### Earlier unsigned and self-signed attempts

A self-signed code-signing certificate was created, imported, and used. It signs
correctly and produces a designated requirement that is stable across rebuilds:

```text
designated => identifier com.nwokolo24.keyward and certificate root = H"65cfc41d…"
```

Two builds of the same source produced byte-different binaries with **identical**
requirements. Despite that, every combination still blocks:

| Attempt | Cross-build read |
| --- | --- |
| Default ACL, unsigned, different paths | blocked |
| Default ACL, unsigned, **same path**, rebuilt in place | blocked |
| Signed with the self-signed cert, same identifier, different paths | blocked |
| Signed, **same path**, rebuilt and re-signed in place | blocked |
| Explicit `SecTrustedApplicationCreateFromPath(NULL)` access, both builds signed | blocked |
| `SecAccessCreate` with NULL / empty trusted list | blocked |
| `SecACLSetContents(acl, NULL, …)` — documented "any application" | blocked |

For these unsigned and self-signed builds, neither path stability nor a stable
signing identity was sufficient. The Apple Development test above passed.

The most likely remaining variable is trust: the certificate evaluates as
`CSSMERR_TP_NOT_TRUSTED`, so a requirement naming it may be unsatisfiable.
`security add-trusted-cert` in the user domain returned success but changed nothing;
system-domain trust needs `sudo` and was not attempted.

### Unverified paths

- **System-level trust for the self-signed certificate** (`sudo security
  add-trusted-cert -d`). Invasive, and may still not work.
- **An Apple Developer ID.** A real trust anchor, so the requirement would validate.
  Untested, and worth checking whether an employer account is already available
  before paying for one.

### What this means for the storage decision

These earlier failures weakened the case for using the Keychain, which
[design.md](design.md) justified because it avoids writing cryptography. The Apple
Development test now demonstrates a same-certificate rebuild fix; Developer ID
distribution signing remains to be tested.

HASP writes its own encrypted vault, which was attributed here to Linux
portability. This is an equally good reason, and quite possibly the real one.

Three ways forward, in the order worth trying:

1. **Check for an Apple Developer ID** through an employer account. Cheapest if it
   exists, and it is the only attempt with a clear mechanism behind it.
2. **Move storage to an encrypted file**, as HASP does. Removes the entire problem
   class. Costs the "no cryptography to get wrong" advantage.
3. **A long-lived local daemon** holding the only Keychain access, with `keyward run`
   as a thin client over a Unix socket. One approval at login rather than one per
   command, so a rebuild never blocks a non-interactive run. The most work, and
   probably what a mature version looks like.

### Corrections to an earlier version of this entry

Both were tested rather than reasoned about, and both were wrong:

- **A permissive ACL is not available.** `SecAccessCreate` with a NULL trusted list,
  with an empty array, and `SecACLSetContents(acl, NULL, ...)` — the documented "any
  application" form — were all tried. Every one still prompts. So there is no option
  to trade the ACL away for convenience, which is just as well.
- **Delete needs no authorisation.** `/usr/bin/security` removes an item it did not
  create, without a prompt. keyward's OSStatus -25244 on a cross-binary delete is
  therefore a defect in keyward, not a Keychain limitation. It was `SecItemDelete`
  behaving differently from the legacy `SecKeychainItemDelete` that `security` uses.
  Fixed; see below.

The ACL turns out to be doing real work: `/usr/bin/security` could not read a keyward
value. That is a protection layer worth keeping rather than bargaining away.

## 2a-bis. Cross-binary delete fails with OSStatus -25244

**Fixed 2026-10-01. Was medium: a keyward bug, not a platform limit.**

`keyward rm` on an item created by a different build fails with -25244,
errSecInvalidOwnerEdit, while `/usr/bin/security delete-generic-password` removes the
same item with no authorisation at all. Deleting is evidently not gated the way
reading is, so the current implementation is asking for something it does not need.

With the daemon, the process that deletes an item is the one that created it, so
this no longer comes up in normal use. It does come back after a daemon rebuild:
measured, the rebuilt daemon's delete failed with -25244, while the original daemon
binary deleted the same item cleanly. Signing does not help: a rebuild signed with
the same certificate as the item's creator also failed its delete with -25244.

Fixed by deleting through the legacy API: `SecItemCopyMatching` returns a reference,
which `SecKeychainItemDelete` removes. That is what `security` does. An integration
test has `/usr/bin/security` create the item and keyward delete it. Run by hand, a
rebuilt daemon deleted an item the old daemon stored in 0.14s, with no prompt.
`Replace` still uses `SecItemUpdate`. Tested on macOS 27.0.1 during signed
installation verification (2026-10-01): a different daemon build signed with the
same Apple Development certificate replaced the old build's dummy item in under
two seconds, and a read verified the new value by hash. Unsigned cross-build
replacement remains untested.

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
