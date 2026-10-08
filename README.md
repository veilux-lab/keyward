# keyward

Keep API keys and tokens out of the config files your coding tools read.

Keyward moves secrets into the macOS Keychain and leaves references in their place:

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
formula. Installing changes no files and moves no secrets; the daemon starts on
first use. Upgrades may ask once for Keychain access.

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
keyward doctor
```

After migrating, start anything that needs those values through `keyward run --`,
including editors (`keyward run -- code .`); started any other way, a program sees
the `cap://` reference. Migration keeps a private plaintext backup of the original;
remove it with `keyward backups rm ~/.zshrc` once the new file works, then open a
new terminal.
See [the usage guide](doc/install.md) for supported files and more commands.

## Restore or remove

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env   # writes plaintext back; asks for "yes"
keyward uninstall               # removes startup, data, backups, and the package
```

Keychain items are kept; remove them first with `keyward rm <name>` if you want
them gone.

## What it protects

Keyward reduces accidental exposure when a tool reads your config or environment,
and makes no network connections. Any process running as you can ask the daemon
for a value, and a command given a secret can leak it, so it does not stop a
deliberate attempt. See [project status](doc/status.md) for known issues.

MIT licensed. See [LICENSE](LICENSE).
