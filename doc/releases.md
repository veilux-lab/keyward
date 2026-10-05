# Automated releases

The GitHub Actions release workflow is prepared locally. Publishing still needs
the Apple credentials below and approval to push the workflow to `main`. An
end-to-end signed and notarized CI release has not been verified yet.

## What runs

[.github/workflows/release.yml](../.github/workflows/release.yml) runs on pushes
to `main`, the repository's default branch. It can also be started manually from
the Actions page with `main` selected; other branches cannot publish.

Each run checks `make verify` on native Apple Silicon and Intel runners. After
both pass, it builds a universal CLI for macOS 15 or later, signs it with
Developer ID Application, and notarizes and staples a disk image. The signing
identifier stays `com.nwokolo24.keyward`.

The release includes:

- A signed, notarized universal `.dmg` containing the CLI, `LICENSE`, and simple
  `INSTALL.txt` instructions. It has no companion app or installer package.
- A source archive for Homebrew, which continues to build from source.
- `SHA256SUMS` and `release.json` recording the exact source commit and CI run.

The workflow also updates `Formula/keyward.rb` in this repository with the source
archive's URL and checksum. That commit uses `github-actions[bot]` and
`GITHUB_TOKEN`; it carries no AI author or co-author attribution. GitHub does not
trigger another push workflow from a `GITHUB_TOKEN` push, preventing a release
loop. See [GitHub's workflow triggering rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

## Set up Apple credentials

The publisher needs paid Apple Developer membership and a **Developer ID
Application** certificate, rather than an Apple Development certificate. See
[Apple's certificate instructions](https://developer.apple.com/help/account/certificates/create-developer-id-certificates).

In `veilux-lab/keyward`, open **Settings → Secrets and variables → Actions** and
add these repository secrets. [GitHub documents the setup](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE_P12_BASE64` | Base64-encoded `.p12` export containing the Developer ID Application certificate and its private key. |
| `APPLE_CERTIFICATE_PASSWORD` | Password protecting that `.p12` export. |
| `APPLE_SIGNING_IDENTITY` | Exact identity name, such as `Developer ID Application: Your Name (TEAMID)`. |
| `APPLE_NOTARY_KEY_P8` | Complete contents of an App Store Connect **team** API key's `.p8` file. |
| `APPLE_NOTARY_KEY_ID` | That API key's ID. |
| `APPLE_NOTARY_ISSUER_ID` | The team's API issuer ID. |
| `RELEASE_PUBLISH_TOKEN` | Fine-grained GitHub token restricted to `veilux-lab/keyward`, with **Contents: write** and **Workflows: write**. |

The repository owner supplies these credentials through GitHub Secrets. Keep the
key material outside the repository and chat. Apple documents the
[API key, key ID, and issuer used by notarytool](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool).

Enable GitHub Actions for the repository and allow the publishing job to write
repository contents. Branch rules must permit its formula update on `main`.
`GITHUB_TOKEN` is supplied by GitHub for the formula update. The separate release
token also permits queued older commits to publish when `main` has since changed
workflow files; GitHub's built-in token cannot do that. See
[GitHub's release token requirements](https://docs.github.com/en/rest/releases/releases#create-a-release).
Release tags use the separate token; formula pushes always use `GITHUB_TOKEN`
to prevent a release loop. Renew expiring tokens in GitHub Secrets.
Missing credentials or failed signing or notarization fail the release. There is
no unsigned fallback, and credential values are not printed in workflow logs.

## Versions and reruns

The version is `0.1.(GITHUB_RUN_NUMBER + 1)`: run 1 uses `0.1.2`, run 2 uses
`0.1.3`, and so on. Failed runs can leave gaps. Rerunning a workflow run keeps
the same version. Once public, release assets are retained rather than overwritten.
Queued publishing jobs retain up to 100 pending runs instead of canceling older
pushes. A later-finishing older run cannot downgrade the formula. CI validates
the exact source archive with `brew install` and `brew test` before publication.

After credentials are configured, an approved push to `main` starts the release
automatically. Manual runs use the same checks and publication steps. Inspect
the Actions result and release artifacts before treating the first release as
verified.

## Using the prebuilt CLI

A work Mac can use the downloaded binary without an Apple login, Go, or Xcode.
Follow `INSTALL.txt` to install it and manage startup with `keyward service`.
Source builds and development tests still need macOS, Go/cgo, and Apple's command
line tools; `make verify` also uses Python 3. Homebrew remains the
[source-built installation](homebrew.md).

Switching from Apple Development or Homebrew builds to Developer ID can prompt
for access to existing Keychain items. Keeping the signing identifier does not
guarantee the same access across different signing identities. Prompt-free
certificate renewal and Developer ID upgrades remain untested.
