# Agent instructions

keyward keeps secrets out of what AI coding agents read. It replaces values in rc
files with `cap://name` references and stores the values in an encrypted vault
whose key is in the macOS Keychain. Go
and cgo, macOS only, MIT, a personal project.

## Start here

1. [doc/status.md](doc/status.md): the current state, known issues, and what can be
   worked on next. Update it when something lands.
2. [doc/design.md](doc/design.md) for why things are the way they are, and
   [doc/obstacles.md](doc/obstacles.md) for what was hard or failed. Read the
   section you need, not the whole file.

## How work is done

- **Test first.** Write the test, watch it fail, then implement. Logic is tested
  against `vault.Memory`. `vault.Encrypted` (the vault) and
  `internal/vault/keychain_darwin.go` (which holds its key) are held to the same
  contract suite (`vault/vaulttest`).
- `make verify` must pass before every commit. Run `make test-integration` when
  the Keychain layer changes.
- Keep comments short: say why, not what. Match the surrounding code. No dead code;
  the owner reviews every line.
- Plans say what gates the work, not how long it takes.

## Secrets and the Keychain

- Never print, log, or put a secret value in argv; compare by hash. Errors must not
  quote values.
- Never run `keyward migrate` against the owner's real files, or read their real
  secrets, unless asked. Use `KEYWARD_SERVICE` and `KEYWARD_VAULT` (on the daemon)
  and `KEYWARD_SOCKET` (on every command) to work under a throwaway service and
  vault, with one or two dummy items. Afterwards delete the vault file and the
  `<service>-vault-key` Keychain item.
- Reading an item another build created puts up a dialog. Before any such test, tell
  the owner to click **Deny**, and time the read. "It finished" does not prove there
  was no dialog: only a read that succeeds in well under two seconds does.
  [scripts/test-apple-dev-signing.sh](scripts/test-apple-dev-signing.sh) shows the
  pattern.
- Deleting another build's item needs no authorisation, so cleanup never prompts.

## Signing on this Mac

The personal Mac has a free **Apple Development** certificate (find it with
`security find-identity -v -p codesigning`). A daemon signed with it keeps Keychain
access across rebuilds:

```sh
go build -o bin/keyward ./cmd/keyward
codesign --force --sign "Apple Development: …" --identifier com.nwokolo24.keyward bin/keyward
```

It is for local use only. Prebuilt Developer ID-signed and notarized distribution
needs paid Apple membership. Source-built Homebrew distribution does not; each
daemon upgrade asks once to read the vault key. See doc/homebrew.md.

## Git

- Commit locally as:
  `git -c user.name="Bueze Nwokolo" -c user.email="55523993+nwokolo24@users.noreply.github.com" commit`
- Do not add Claude or other AI tools as authors or co-authors of commits or PRs.
- **Never push**, or create, change, or delete a remote branch or pull request,
  without the owner's explicit approval given just before that action. Say the repo,
  the branch, and the action when asking. An earlier approval does not cover the
  next push.
- Remote: `git@github.com:veilux-lab/keyward.git`, branch `main`.
