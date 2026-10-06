# keyward

Keep API keys and tokens out of the config files your coding tools read.

Keyward stores secrets in the macOS Keychain and replaces their values with
references:

```sh
export API_TOKEN='cap://api-token'
```

Your shell config holds the reference. When a command needs the real value,
`keyward run` supplies it through the command's environment.

## Install

macOS only. Homebrew builds from source using Go and Apple's command line tools;
you do not need a paid Apple Developer account.

```sh
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git
brew install veilux-lab/keyward/keyward
```

Homebrew 7 warns that the tap is not trusted, then trusts only this formula.
Run these as your normal user. Installation does not change your shell files or
move any secrets. The daemon starts when you first add, list, or resolve
secrets. See [Homebrew setup](doc/homebrew.md) to start it during installation. A
[signed local installation](doc/install.md#signed-local-installation) is also available.

## Use

Preview the changes, then migrate your shell config:

```sh
keyward migrate --dry-run ~/.zshrc
keyward migrate ~/.zshrc
```

Migration shows what will move without printing secret values and asks you to
type `yes`. It keeps a timestamped plaintext backup beside the original file.
Check the result, then delete backups you no longer need. Open a new terminal
so your environment uses the references.

Run commands that need those secrets through Keyward:

```sh
keyward run -- npm test
```

You can also add a secret from the clipboard and check your setup:

```sh
pbpaste | keyward add api-token
keyward ls                  # names only
keyward doctor
```

See [the usage guide](doc/install.md) for supported files and more commands.

## Restore or remove

To put current stored values back into selected files, preview and restore them
before stopping the daemon:

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env
keyward service uninstall
brew uninstall veilux-lab/keyward/keyward
```

Choose the files you migrated. Restoration writes plaintext again and requires
`yes`. Check any reported skips before uninstalling. Keychain items are retained.

## What it protects

Keyward reduces accidental exposure when a tool reads your config or environment.
Any process running as you can ask the daemon to resolve a reference, and a
command receiving a secret can print or transmit it. This does not prevent a
deliberate attempt to obtain credentials.

Homebrew daemon upgrades may prompt for access to older Keychain items. See
[Homebrew setup and upgrades](doc/homebrew.md) and [project status](doc/status.md).

See [GitHub Actions release setup](doc/releases.md) for free source releases and
optional signed downloads.

MIT licensed. See [LICENSE](LICENSE).
