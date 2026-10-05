# Automated releases

The default release publishes free source/Homebrew packages. It needs no Apple
credentials or personal access token. This default is prepared locally and
awaits an approved push to `main`; it has not published a release yet. The earlier
CI run passed native Apple Silicon and Intel checks, then stopped at its old
publisher-token requirement.

## What runs

[.github/workflows/release.yml](../.github/workflows/release.yml) runs on pushes
to `main`, the repository's default branch. Manual runs from the Actions page
must also select `main`; other branches cannot publish.

Each successful run:

1. Runs `make verify` and builds the CLI on native Apple Silicon and Intel runners.
2. Creates a source archive from the triggering commit and checks that exact
   archive with a disposable Homebrew source installation and `brew test`.
3. Publishes `keyward-<version>.tar.gz`, `SHA256SUMS`, and `release.json`, which
   records the source commit and CI run. It then updates this repository's
   `Formula/keyward.rb` with the archive URL and checksum.

The formula commit uses `github-actions[bot]` and the built-in `GITHUB_TOKEN`,
without AI author or co-author attribution. GitHub does not trigger another push
workflow from that token's push, preventing a release loop. See
[GitHub's triggering rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

Enable Actions and allow the publishing job to write repository contents.
Branch rules must permit its formula update on `main`. GitHub supplies
`GITHUB_TOKEN` automatically.

## Versions and reruns

The version is `0.1.(GITHUB_RUN_NUMBER + 1)`: run 1 uses `0.1.2`, run 2 uses
`0.1.3`, and so on. Failed runs can leave gaps. Rerunning a workflow run keeps
the same version. Public release assets are retained rather than overwritten.
Queued publishing jobs retain pending pushes, and an older run cannot downgrade
the formula.

Normally, the built-in token is enough. For a queued older commit that changes
workflow files relative to current `main`, GitHub may require a token with
additional permissions. If that case is needed, add an optional
`RELEASE_PUBLISH_TOKEN` repository secret: a fine-grained GitHub token restricted
to `veilux-lab/keyward`, with **Contents: write** and **Workflows: write**.
It is for release publication; formula pushes continue using `GITHUB_TOKEN`.
This is a GitHub permission requirement, independent of Apple membership. See
[GitHub's release token rules](https://docs.github.com/en/rest/releases/releases#create-a-release).

## Optional signed downloads

Paid Apple membership is needed only for the optional Developer ID-signed,
notarized download. To enable it, configure the six repository secrets below,
then set the repository Actions **variable** `KEYWARD_SIGNED_RELEASES` to exactly
`true`. It defaults to false; adding Apple secrets alone does not enable signing.

Open **Settings → Secrets and variables → Actions** in `veilux-lab/keyward`.
[GitHub documents repository secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE_P12_BASE64` | Base64-encoded `.p12` containing the Developer ID Application certificate and its private key. |
| `APPLE_CERTIFICATE_PASSWORD` | Password protecting that `.p12`. |
| `APPLE_SIGNING_IDENTITY` | Exact `Developer ID Application: Your Name (TEAMID)` identity. |
| `APPLE_NOTARY_KEY_P8` | Complete contents of an App Store Connect **team** API key's `.p8` file. |
| `APPLE_NOTARY_KEY_ID` | That API key's ID. |
| `APPLE_NOTARY_ISSUER_ID` | The team's API issuer ID. |

The owner supplies these through GitHub Secrets. Keep private key material out
of the repository and chat. See [Apple's Developer ID certificate setup](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
and [notarytool API credentials](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool).

When enabled, the workflow adds a signed, notarized, stapled universal `.dmg` for
macOS 15 or later. It contains the CLI, `LICENSE`, and `INSTALL.txt`, with signing
identifier `com.nwokolo24.keyward`. Missing credentials or failed signing or
notarization fail that release; it never silently falls back to unsigned output.
Credential values are not printed. Signed CI publication remains unverified.

A work Mac can use that prebuilt CLI without an Apple login, Go, or Xcode.
Switching from Homebrew or Apple Development builds may require Keychain approval.
Prompt-free Developer ID upgrades and certificate renewal remain untested.

Free Apple Development signing is available for [personal local installation](install.md#signed-local-installation).
It is distinct from Developer ID distribution and notarization. Homebrew source
releases remain free and independent of either certificate. Source builds still
need macOS, Go/cgo, and Apple's command line tools; `make verify` also uses Python 3.
