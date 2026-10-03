# Source-built Homebrew distribution

The first Homebrew package builds the CLI from source. It uses `brew services`
for login startup and does not require an Apple certificate, notarization, or the
native status app. The signed local installer remains available separately.

## Install

Release `v0.1.0` and its source archive are public in
[veilux-lab/homebrew-tap](https://github.com/veilux-lab/homebrew-tap).
The public download checksum, source installation, and formula test were verified
on the development Mac. First-user Keychain prompts and login startup on a fresh
Mac remain untested.

```sh
brew tap veilux-lab/tap
brew install veilux-lab/tap/keyward
keyward service install
keyward service status
```

The formula lives in `veilux-lab/homebrew-tap`. It builds with Go and cgo against
macOS Security.framework, injects the release version and Homebrew executable
path, and starts `opt_bin/keyward daemon`. No secret migration happens during
installation. Startup is an explicit user action; the formula does not enable it
in `post_install`.
The explicit service label `com.veilux-lab.keyward.homebrew` avoids dependence on
Homebrew's default label, which varies between releases.
The fully qualified installation command grants formula-specific trust when
required. Installing by short name from an untrusted tap requires
`brew trust --formula veilux-lab/tap/keyward` first; see
[Homebrew's tap trust documentation](https://docs.brew.sh/Tap-Trust).

`keyward service install` delegates to `brew services restart
veilux-lab/tap/keyward`. It refuses to start over another daemon or the signed
local login agent. Status checks both launchd registration and the broker's socket.
Uninstall keeps the existing restoration warning and exact-`yes` confirmation,
then calls `brew services stop`. Homebrew owns the executable and startup files;
Keyward does not copy them into a second installation.

After an upgrade, restart the daemon. A changed source-built daemon can trigger
Keychain access prompts for older items. Restarting an unchanged build should keep
access, but source distribution does not inherit the Apple-signed upgrade guarantee.
Keychain entries remain after service shutdown, formula removal, and reinstall.

Before removing the formula, users may explicitly restore selected files:

```sh
keyward restore --dry-run ~/.zshrc .env
keyward restore ~/.zshrc .env
keyward service uninstall
brew uninstall keyward
```

`brew uninstall` does not automatically restore plaintext or invoke Keyward's
interactive warning. The formula caveats and installation documentation present
these steps before removal. The Homebrew daemon uses default logging settings;
environment overrides passed to an individual CLI do not configure that service.

## Prepare a release locally

Commit the tested source first, then run:

```sh
go run ./cmd/keyward-release -version 0.1.0 -out bin/homebrew
cp packaging/homebrew/README.md bin/homebrew/README.md
```

The command uses `git archive` at the current commit and creates:

- `bin/homebrew/keyward-0.1.0.tar.gz`: tracked source only, without Git history or
  untracked files.
- `bin/homebrew/Formula/keyward.rb`: versioned download URL and exact archive
  SHA-256, with a source build, service definition, caveats, and formula test.
- `bin/homebrew/README.md`: the reviewed tap installation and removal instructions.

Tracked uncommitted changes and existing output files are refused. The archive's
filename and download URL use the same version as the CLI. The template is retained
in `internal/homebrew/keyward.rb.tmpl`; rerun the command for each new release.
The release URL is an asset on the public tap repository, allowing the primary
source repository to remain private while publishing a reviewed source snapshot.

## Publication gates for future releases

Before publishing a new version:

1. Verify the generated formula locally with a source install, `brew test`, style
   checks, and daemon smoke testing under a separate socket and Keychain service.
2. Obtain the owner's explicit approval to create the public
   `veilux-lab/homebrew-tap` repository, publish the source archive as release
   `v0.1.0`, and push the formula to its `main` branch. Publishing the archive
   makes that source snapshot publicly readable.
3. Authenticate GitHub publication with `gh auth login` without sharing
   credentials in chat.
4. Upload the exact archive used for the formula checksum. Push the formula and a
   tap README containing setup, upgrade, restoration, and uninstall instructions.
5. Verify the public download checksum, installation, and formula test. Verify
   first-user prompts and login startup on a fresh Mac separately; an install on
   the development Mac does not establish those behaviors.

A paid Apple Developer account is only a gate for a later Developer ID-signed and
notarized prebuilt distribution, not for this source formula.
