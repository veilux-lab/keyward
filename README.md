# keyward

**Your dotfiles are safe from the internet, not from your AI agents.**

`~/.zshrc`, `~/.bashrc`, `~/.profile` and `.env` files hold tokens that every
agent working on your machine can read. Keyward moves those secrets into an
encrypted vault whose key is held in the macOS Keychain.

Each value is replaced by a reference:

```sh
export API_TOKEN='cap://api-token'
```

`keyward run` supplies the real value only to the command that needs it.

## Install

Apple Silicon Macs, with Homebrew:

```sh
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git
brew install veilux-lab/keyward/keyward
```

Run the `brew tap` line first; without it, `brew install` fails with "Repository
not found". Homebrew warns that the tap is not trusted, then trusts only this
formula. Installing changes no files and moves no secrets. On first use the daemon
starts and keyward writes `~/.agents/keyward.md`, instructions for AI agents.
Upgrades may ask once for Keychain access.

Intel Macs: build it yourself. Homebrew no longer ships Go for Intel, so the
formula cannot build there. With [Go](https://go.dev/dl/) and Apple's command line
tools:

```sh
git clone https://github.com/veilux-lab/keyward.git && cd keyward
go build -o keyward ./cmd/keyward
./keyward daemon    # leave running in a terminal
```

For startup at login, sign the build with an Apple Development certificate (a free
one from Xcode works) and install it with `make install
SIGN_IDENTITY='Apple Development: you@example.com (ID)'`. Find your identity with
`security find-identity -v -p codesigning`.

## Use

```sh
keyward migrate --dry-run ~/.zshrc   # preview; values are never printed
keyward migrate ~/.zshrc             # asks for "yes"
keyward run -- npm test
pbpaste | keyward add api-token
keyward ls                           # names only
keyward agents                       # instructions for AI agents, and how to link them
keyward recovery show                # a code that restores the vault key if it is lost
keyward doctor
```

After migrating, start anything that needs those values through `keyward run --`;
started any other way, a program sees the `cap://` reference. In a shell that has
loaded your rc file, `keyward run` resolves every reference there; name just the
ones a command needs with `--only`, as in `keyward run --only GITHUB_TOKEN -- gh pr list`. Do not start your
editor that way: every agent and terminal inside it would get the real values.

Migration keeps an encrypted backup of the original, with its key in the vault;
remove both with `keyward backups rm ~/.zshrc` once the new file works, then open a
new terminal.

`migrate` and `restore` work on shell startup files, shell scripts, and `.env`
files. Run `keyward help` for every command.

## MCP servers

An MCP server that reads a migrated variable gets the `cap://` reference instead
of the token, and fails to connect. Run each one through keyward, so only that
server gets its secret:

```sh
keyward mcp     # lists affected servers in Claude Code, Codex, and Cursor
```

It prints the replacement definition for each, in that tool's format, and never
edits the config itself. A remote server goes through the `mcp-remote` bridge,
with its header filled in after keyward resolves the token. Servers that read a
variable from the editor's environment without naming it in their config cannot
be detected; wrap those by hand the same way.

## Restore or remove

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env   # writes plaintext back; asks for "yes"
keyward uninstall               # removes keyward; secrets stay in the vault
keyward uninstall --purge       # also deletes the vault and its key
```

Restore first: uninstall lists every file that still uses `cap://` references,
with the command that restores it. `--purge` refuses until no file does, because
a purged vault cannot be recovered.

## What it protects

Keyward reduces accidental exposure when a tool reads your config or environment,
and makes no network connections. Any process running as you can ask the daemon
for a value, and a command given a secret can leak it, so it does not stop a
deliberate attempt. Activity, names and outcomes but never values, is logged to
`~/Library/Logs/keyward/activity.jsonl`.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

MIT licensed. See [LICENSE](LICENSE).
