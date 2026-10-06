# Homebrew

Homebrew packaging lives alongside the source in
[`veilux-lab/keyward`](https://github.com/veilux-lab/keyward). Releases supply
source archives and prebuilt bottles from the same repository. Bottles cover
Apple Silicon and Intel Macs with Homebrew in its default location, so installing
needs neither Go nor a compiler there. Other setups build from source with Go and
Apple's command line tools. No signing certificate or paid Apple Developer
membership is required. A separate
[signed CLI installation](install.md#signed-local-installation) is also available.

Release [`v0.1.3`](https://github.com/veilux-lab/keyward/releases/tag/v0.1.3) adds
first-use startup, the optional installer below, and CLI-only local installation.
`v0.1.1` requires explicit `keyward service install`. `v0.1.2` was never published.

## Install

```sh
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git
brew install veilux-lab/keyward/keyward
```

The explicit URL lets Homebrew use this repository as a tap without a separate
`homebrew-*` repository. The fully qualified formula name also handles
formula-specific trust on Homebrew versions that require it. Homebrew 7 still
warns that the tap is not trusted before it trusts the formula; the warnings are
expected. Homebrew's own caveat suggests `brew services start`; prefer
`keyward service install`, which also re-enables startup after service uninstall.

Run commands as your normal user, without `sudo`. Installing the formula does
not migrate secrets or change your shell config. From `v0.1.3`, the daemon starts through `brew services` when a command first needs the Keychain;
subsequent logins start it automatically. Help, version, status, and `run` without references
leave it stopped. You can start it sooner with `keyward service install`.

### Start during installation

The tap also provides an optional installer command:

```sh
brew trust --command veilux-lab/keyward/keyward-install
brew keyward-install --start-daemon
```

Run these after tapping the repository. The installer finishes the normal source
installation, then starts the daemon immediately and enables login startup.
Without `--start-daemon`, it leaves startup for first use. The command-specific
trust is separate from the formula's trust.

This is a [Homebrew external command](https://docs.brew.sh/External-Commands),
kept in [cmd/brew-keyward-install](../cmd/brew-keyward-install). It runs startup
after `brew install` finishes, outside the formula's post-install sandbox.

The formula is [Formula/keyward.rb](../Formula/keyward.rb). It injects the release
version and Homebrew executable path, then runs `opt_bin/keyward daemon` under the
stable service label `com.veilux-lab.keyward.homebrew`.
`keyward service install` delegates to `brew services restart
veilux-lab/keyward/keyward`. It refuses to start over another daemon or the signed
local login agent. `service status` checks launchd registration and the socket.
First-use startup uses `brew services start` for an unloaded service and respects
`keyward service uninstall`: that command saves a private disabled marker, so a
later vault command cannot turn startup back on. Explicit `service install`
re-enables it. Custom sockets and Keychain service names remain manual.
Using `brew services stop` directly only stops the service; it does not save this
choice, so the next vault request can start it again. Use `keyward service
uninstall` when you want it to stay disabled.

## Upgrade

```sh
brew upgrade veilux-lab/keyward/keyward
keyward service install
```

The second command restarts the daemon. A changed daemon, bottled or built from
source, may prompt for macOS approval to read previously stored Keychain items.
Homebrew upgrades do not promise prompt-free daemon restarts. The Homebrew daemon uses the default
[logging limits](install.md#activity-logs); environment overrides on an individual
CLI do not configure that service.

### Switch from the original tap

The original `veilux-lab/homebrew-tap` repository was deleted on October 4, 2026.
Existing `v0.1.0` installations can switch using their local tap checkout:

```sh
"$(brew --prefix veilux-lab/tap/keyward)/bin/keyward" service uninstall
brew uninstall veilux-lab/tap/keyward
brew untap veilux-lab/tap
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git
brew install veilux-lab/keyward/keyward
keyward service install
keyward service status
```

Run the first command with the old CLI, before removing it. Confirm its service
shutdown warning with `yes`. Keep the existing `cap://` references; the stored
items stay in your Keychain and can be used by the new daemon. This change needs
no restoration or second migration. The new build may prompt for Keychain access.
Keep the old local tap until its service is stopped and formula removed. Removing
it before adding the new tap also avoids updates against the deleted repository.
Fresh installs and uncached source downloads from the original tap are unavailable.

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
and reinstall. Service uninstall keeps first-use startup disabled until explicit
`keyward service install`. `brew uninstall` does not restore files or run
Keyward's warning and confirmation flow.

## Prepare a release

The default [GitHub Actions release workflow](releases.md) prepares free source
releases and bottles on pushes to `main`, verifies them with `brew test`, then
publishes them before advancing this repository's formula. No Apple credentials or
personal access token are normally needed. The steps below remain available for
manual releases, which are source-only.

The release tool creates a source archive from a committed Git revision and a
formula containing its exact checksum. The template lives in
[internal/homebrew/keyward.rb.tmpl](../internal/homebrew/keyward.rb.tmpl).

After committing and verifying the source:

```sh
release_version=0.1.2
go run ./cmd/keyward-release -version "$release_version" -out "bin/homebrew-$release_version"
```

For manual recovery, use the failed CI run's version and source commit;
`0.1.2` above is an example. Coordinate manual numbering with CI's `0.1.*`
sequence. The output contains `keyward-<version>.tar.gz` and `Formula/keyward.rb`.
The archive includes tracked source only, without Git history or untracked files. The command
refuses tracked uncommitted changes and existing output files. Its download URL
points to the matching release asset in this repository.

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
3. Upload the exact archive referenced by the formula to the matching release,
   then copy the generated formula into `Formula/keyward.rb`, verify, commit,
   and obtain approval to push that formula update. Keep the formula, source,
   documentation, and releases in this repository.
4. Verify the public download checksum, source installation, and `brew test`.
   Test first-user Keychain prompts and login startup on a fresh Mac separately.

Automated and manual source releases need no Apple membership. Signed and
notarized prebuilt downloads are optional: they require paid Developer ID
membership and an explicit `KEYWARD_SIGNED_RELEASES=true` Actions variable. See
[release setup](releases.md#optional-signed-downloads).
