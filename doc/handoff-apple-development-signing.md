# Handoff: test free Apple Development signing

Instructions for an AI agent on the owner's personal Mac. Read this file, then
follow the steps in order. Nothing else in the repo needs reading unless a step
names it. Your context is limited, so do not explore.

## The one question

When the keyward daemon is rebuilt and signed with the **same Apple Development
certificate** (free Apple account), can the new build read a Keychain item the old
build stored, **without a dialog**?

- **Yes:** paying for a Developer ID is very likely worth it. It would remove the
  last approval prompt from upgrades.
- **No:** signing does not help on this macOS, and the daemon stays the only fix.

## What is already known

From the owner's work laptop and a CI runner, recorded in
[obstacles.md](obstacles.md) section 2a:

| Build that reads the item | macOS 27 laptop | macOS 26 CI runner |
| --- | --- | --- |
| Same binary that stored it | reads, no dialog | reads, no dialog |
| Rebuild, unsigned | dialog | blocked |
| Rebuild, same self-signed certificate | **dialog** | reads, no dialog |
| Rebuild, Apple Development certificate | untested | untested |

A theory, not verified: since macOS 10.12, a Keychain item records a *partition*
for the program that created it, as `teamid:XXXXXXXXXX` for a program with an
Apple-issued team ID and `cdhash:...` otherwise. A self-signed certificate has no
team ID (`codesign` reports `TeamIdentifier=not set`), so every rebuild may count as
a new program. An Apple Development certificate has a team ID, even on a free
account. If the theory holds, this test passes.

## Rules

- Use only the dummy item the script creates. Never read, print, or migrate the
  owner's real secrets, and never run `keyward migrate` on a real file.
- **Never decide "no dialog" from a command merely finishing.** An approved dialog
  and no dialog look the same afterwards. The owner clicks **Deny** on every keyward
  dialog, and the script times each read. Only `READ` in under 2 seconds counts as
  no dialog.
- Tell the owner which dialogs to expect **before** running the script (step 3).
- Do not change system trust settings, the default keychain, or the owner's shell
  rc files.
- Commit locally when done, but **do not push** without the owner's explicit
  approval, given just before the push. Name the repo, the branch, and the action
  when asking.

## Step 1: prerequisites

Check, and ask the owner to install anything missing:

```sh
sw_vers -productVersion        # record it; the result may depend on the macOS version
go version                     # needs 1.26 or later
xcode-select -p                # needs the full Xcode app, not just the command line tools
```

The full Xcode app (from the App Store) is needed because a free account can only
create a signing certificate through Xcode.

The repo is private: `git@github.com:nwokolo24/keyward.git`, branch `main`. The
owner clones it as GitHub user nwokolo24.

## Step 2: create the certificate (the owner does this)

The owner signs in with their personal Apple ID. You cannot do this step.

1. Xcode → Settings → Accounts → **+** → Apple ID, and sign in.
2. Select the account's **Personal Team**, then **Manage Certificates…**
3. **+** → **Apple Development**. Close the window.

Then confirm the identity exists and copy its exact name:

```sh
security find-identity -v -p codesigning
```

You are looking for a line like `1) 4F3A… "Apple Development: name@example.com (AB12CD34EF)"`.
The quoted string is the identity. If only a `keyward-dev-signing` identity
appears, that is the self-signed one from earlier; do not use it.

## Step 3: tell the owner what to expect, then run

Say this to the owner first:

> Two kinds of dialog may appear. **`codesign wants to access key …`**: click
> **Allow** (or Always Allow); that is your signing key, and the test needs it.
> It may appear twice. **Any dialog naming `kwd-b` or `kwd-unsigned`**: click
> **Deny**. That dialog is the result we are measuring, so note its exact wording.

Then run, from the repo root, with the identity from step 2:

```sh
scripts/test-apple-dev-signing.sh "Apple Development: name@example.com (AB12CD34EF)"
```

The script builds three daemons (`kwd-a` and `kwd-b` signed, `kwd-unsigned` not), stores
one dummy item with `kwd-a`, then has each daemon try to read it. It cleans up its
item and temporary files when it exits. A read that nobody answers gives up after
two minutes.

## Step 4: interpret

The output ends with three lines like `kwd-b   READ   0.06s`.

| `kwd-a` | `kwd-b` | `kwd-unsigned` | Meaning |
| --- | --- | --- | --- |
| READ, fast | READ, under 2s | BLOCKED | **Pass.** Apple Development signing survives a rebuild. |
| READ, fast | BLOCKED | BLOCKED | **Fail.** Signing does not help here either. |
| READ, fast | READ, slow | — | Inconclusive: the owner probably clicked Allow. Run again. |
| — | — | READ | The test is not sensitive on this machine; the result proves nothing. |
| BLOCKED | — | — | Setup problem; see troubleshooting. |

Also note:

- the `team=` value on the `kwd-a` and `kwd-b` lines; it should be a 10-character team ID, not `not set`;
- the `requirement:` line;
- the owner's exact dialog wording;
- whether a codesign dialog appeared.

## Step 5: record and commit

Keep everything you write short, and explain why rather than narrating.

1. In [obstacles.md](obstacles.md), add a subsection under section 2a, after
   "Self-signed signing, retested (2026-10-01)", titled
   `### Apple Development signing, tested (<date>)`. Include:
   - the macOS version;
   - the three results with their timings;
   - the team ID, as present or not set (the ID itself is not needed);
   - the dialog wording;
   - the meaning, from the table above.
2. In the same section, update the "What remains" bullet that says "A Developer ID
   is untested". Say what this result implies, and that a free certificate cannot
   be used for distribution to other people (only a Developer ID can, and it needs
   the paid programme).
3. In [status.md](status.md), update the `Code signing` row to match.
4. Commit:

   ```sh
   git add doc/obstacles.md doc/status.md
   git -c user.name="Bueze Nwokolo" -c user.email="55523993+nwokolo24@users.noreply.github.com" \
     commit -m "Record Apple Development signing result"
   ```

5. Report the result to the owner in a few lines, then ask before pushing.

## Troubleshooting

- **`codesign` fails with `errSecInternalComponent`**: the signing key could not
  be used, usually because the codesign dialog was denied or the session has no GUI
  (for example SSH). Run from Terminal on the Mac itself, and Allow the dialog.
- **`daemon … did not start`**: the script prints the daemon log. Another daemon
  using the same temporary socket is impossible, so it is usually a build error
  printed earlier.
- **The script hangs for two minutes**: a dialog is waiting behind another window.
  Ask the owner to look for it and click Deny.
- **The identity is not found**: the certificate is missing or expired. Check it in
  Xcode's Manage Certificates, or create a new one.

## If it passes, optional follow-ups

Do these only if the owner asks.

- **Upgrade path:** store with `kwd-a` signed by the old certificate and read with a
  build signed by a newly created Apple Development certificate. That shows whether
  a certificate renewal costs one more round of approvals.
- **Developer ID:** a Developer ID certificate needs a paid team, whose team ID
  differs from the free Personal Team's. A pass here predicts that a Developer ID
  build reads items a previous Developer ID build stored, but not items stored
  under the free team.
