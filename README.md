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

For startup at login, see [signed local installation](doc/install.md#signed-local-installation).

## Use

```sh
keyward migrate --dry-run ~/.zshrc   # preview; values are never printed
keyward migrate ~/.zshrc             # asks for "yes"
keyward run -- npm test
pbpaste | keyward add api-token
keyward ls                           # names only
keyward agents                       # instructions for AI agents, and how to link them
keyward doctor
```

After migrating, start anything that needs those values through `keyward run --`,
including editors (`keyward run -- code .`); started any other way, a program sees
the `cap://` reference. Migration keeps an encrypted backup of the original, with its key in the Keychain;
remove both with `keyward backups rm ~/.zshrc` once the new file works, then open a
new terminal.
See [the usage guide](doc/install.md) for supported files and more commands.

## Restore or remove

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env   # writes plaintext back; asks for "yes"
keyward uninstall               # removes startup, data, backups, and the package
```

Stored secrets are kept; remove them first with `keyward rm <name>` if you want
them gone.

## What it protects

Keyward reduces accidental exposure when a tool reads your config or environment,
and makes no network connections. Any process running as you can ask the daemon
for a value, and a command given a secret can leak it, so it does not stop a
deliberate attempt. See [project status](doc/status.md) for known issues.

MIT licensed. See [LICENSE](LICENSE).
