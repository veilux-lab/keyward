# Homebrew

Homebrew packaging lives alongside the source in
[`veilux-lab/keyward`](https://github.com/veilux-lab/keyward). Releases supply
source archives from the same repository. The formula builds on macOS using Go
and Apple's command line tools. No signing certificate or paid Apple Developer
membership is required. The signed status app is available through the separate
[local installer](install.md#signed-local-installation).

Release [`v0.1.1`](https://github.com/veilux-lab/keyward/releases/tag/v0.1.1) uses
this single-repository setup.

## Install

```sh
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git
brew install veilux-lab/keyward/keyward
keyward service install
keyward service status
```

The explicit URL lets Homebrew use this repository as a tap without a separate
`homebrew-*` repository. The fully qualified formula name also handles
formula-specific trust on Homebrew versions that require it.

Run startup commands as your normal user, without `sudo`. The daemon uses your
login Keychain and starts now and at login through `brew services`. Installing
the formula does not migrate secrets, change your shell config, or enable startup.

The formula is [Formula/keyward.rb](../Formula/keyward.rb). It injects the release
version and Homebrew executable path, then runs `opt_bin/keyward daemon` under the
stable service label `com.veilux-lab.keyward.homebrew`.
`keyward service install` delegates to `brew services restart
veilux-lab/keyward/keyward`. It refuses to start over another daemon or the signed
local login agent. `service status` checks launchd registration and the socket.

## Upgrade

```sh
brew upgrade veilux-lab/keyward/keyward
keyward service install
```

The second command restarts the daemon. A changed source-built daemon may prompt
for macOS approval to read previously stored Keychain items. Source builds do not
promise prompt-free upgrades. The Homebrew daemon uses the default
[logging limits](install.md#activity-logs); environment overrides on an individual
CLI do not configure that service.

### Switch from the original tap

Once `v0.1.1` is published, replace an existing `v0.1.0` installation with:

```sh
"$(brew --prefix veilux-lab/tap/keyward)/bin/keyward" service uninstall
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git
brew uninstall veilux-lab/tap/keyward
brew install veilux-lab/keyward/keyward
keyward service install
keyward service status
```

Run the first command with the old CLI, before removing it. Confirm its service
shutdown warning with `yes`. Keep the existing `cap://` references; the stored
items stay in your Keychain and can be used by the new daemon. This change needs
no restoration or second migration. The new build may prompt for Keychain access.
After switching, the old tap can be removed with `brew untap veilux-lab/tap`.

If moving from a signed local installation, stop it using that installation's
`keyward service uninstall` first. Ensure your PATH selects Homebrew's CLI rather
than the old `~/.local/bin/keyward`. Changing daemon builds may prompt for Keychain
approval. First-user prompts and actual login startup on a fresh Mac remain untested.

## Restore and uninstall

Choose the files you migrated. Restore them explicitly if you want the current
stored values back in plaintext:

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env
keyward service uninstall
brew uninstall veilux-lab/keyward/keyward
```

Restore and service uninstall each require exact lowercase `yes`. Review any
restoration skips before removal. Keychain items remain after shutdown, removal,
and reinstall. `brew uninstall` does not restore files or run Keyward's warning
and confirmation flow.

## Prepare a release

The release tool creates a source archive from a committed Git revision and a
formula containing its exact checksum. The template lives in
[internal/homebrew/keyward.rb.tmpl](../internal/homebrew/keyward.rb.tmpl).

After committing and verifying the source:

```sh
go run ./cmd/keyward-release -version 0.1.1 -out bin/homebrew-0.1.1
cp bin/homebrew-0.1.1/Formula/keyward.rb Formula/keyward.rb
```

The output contains `keyward-0.1.1.tar.gz` and `Formula/keyward.rb`. The archive
includes tracked source only, without Git history or untracked files. The command
refuses tracked uncommitted changes and existing output files. Its download URL
points to the archive asset on this repository's `v0.1.1` release.

Test the generated formula before committing it. Do not regenerate the archive
from the formula-update commit: publish the exact archive used for the recorded
checksum. For subsequent releases, substitute the new version in both the version
argument and output directory so earlier artifacts are not overwritten.

## Publish a release

Publication requires the repository to be public. Making the complete repository
public also exposes its Git history, unlike publishing a source archive alone.

1. Run `make verify`. Verify the formula with a source install, `brew test`, style
   checks, and a daemon smoke test using a separate socket and throwaway Keychain
   service. Delete the dummy items afterwards.
2. Obtain the owner's explicit approval immediately before pushing the formula
   commit to `veilux-lab/keyward` on `main`, and before publishing the tag and
   release assets. Name the repository, branch, and action in the request.
3. Upload the exact archive referenced by the formula to the matching release.
   Keep the formula, source, documentation, and releases in this repository.
4. Verify the public download checksum, source installation, and `brew test`.
   Test first-user Keychain prompts and login startup on a fresh Mac separately.

No Apple membership is needed for this source release. A future signed and
notarized prebuilt release would need paid Developer ID membership.
