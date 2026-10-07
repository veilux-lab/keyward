# Homebrew 101, and how Keyward uses it

## Homebrew in six words

| Term | What it is | Keyward's |
| --- | --- | --- |
| **Formula** | A Ruby recipe: where to download, how to build, how to test | [Formula/keyward.rb](../Formula/keyward.rb) |
| **Tap** | A Git repository of formulas that you add to Homebrew | This repository, `veilux-lab/keyward` |
| **Bottle** | A prebuilt, ready-to-unpack copy of an installed formula | One per release, for Apple Silicon |
| **Cellar** | Where installed versions live; `bin` links point into it | `/opt/homebrew/Cellar/keyward/<version>` |
| **Service** | A background job Homebrew registers with macOS `launchd` | The Keyward daemon |
| **Trust** | Homebrew 7's opt-in before it loads a third-party formula | Granted to the Keyward formula only |

## What `brew install` does

```mermaid
flowchart TD
    A["brew install owner/tap/formula"] --> B{"Tap already added?"}
    B -- no --> C["Clone github.com/owner/homebrew-tap"]
    B -- yes --> D["Read the formula"]
    C --> D
    D --> E{"Trusted?"}
    E -- no --> F["Refuse, or trust when the full name was given"]
    F --> G
    E -- yes --> G{"Bottle for this Mac?"}
    G -- yes --> H["Download the bottle, check its sha256, unpack"]
    G -- no --> I["Install build tools, download source, check sha256, build"]
    H --> J["Link into /opt/homebrew/bin and print caveats"]
    I --> J
```

The formula pins a checksum for every download, so a tampered file fails the
install. Homebrew asks "proceed?" only when it must also install or upgrade other
packages.

## How Keyward is packaged

```mermaid
flowchart LR
    subgraph repo["github.com/veilux-lab/keyward"]
        code["Go source"]
        formula["Formula/keyward.rb"]
    end
    subgraph release["GitHub release vX.Y.Z"]
        src["keyward-X.Y.Z.tar.gz"]
        bottle["keyward-X.Y.Z.arm64_sequoia.bottle.tar.gz"]
    end
    formula -- "url + sha256" --> src
    formula -- "bottle root_url + sha256" --> bottle
    user["brew install"] --> formula
```

Three choices worth knowing:

- **One repository is both the code and the tap.** Homebrew assumes a tap called
  `homebrew-keyward`, so users add ours by URL first. Skipping that step gives
  "Repository not found".
- **Apple Silicon gets a bottle.** No Go and no compiler are needed, and the user's
  own Go is never upgraded. Intel Macs build it themselves; Homebrew no longer
  ships Go for Intel.
- **The daemon is a Homebrew service.** `keyward` starts it on first use through
  `brew services` and macOS starts it again at each login.

## How a release happens

Nobody edits the formula by hand. Every code push to `main` runs
[.github/workflows/release.yml](../.github/workflows/release.yml):

```mermaid
flowchart TD
    push["Push to main (doc-only pushes skip this)"] --> verify["Test on Apple Silicon and Intel"]
    verify --> source["Archive the exact commit"]
    source --> bottle["Build the bottle, then reinstall from it and run brew test"]
    bottle --> publish["Publish the GitHub release: archive, bottle, checksums"]
    publish --> bot["Bot commits the new version and checksums to Formula/keyward.rb"]
    bot --> users["brew upgrade sees the new version"]
```

If any step fails, nothing is published and the formula keeps the old version.

## What a user runs

```mermaid
sequenceDiagram
    actor Dev as Engineer
    participant Brew as Homebrew
    participant CLI as keyward
    participant Daemon as keyward daemon
    participant KC as macOS Keychain
    Dev->>Brew: brew tap veilux-lab/keyward with the repo URL
    Dev->>Brew: brew install veilux-lab/keyward/keyward
    Brew-->>Dev: Pours the bottle, prints caveats
    Dev->>CLI: keyward add api-token
    CLI->>Brew: brew services start (first use only)
    Brew->>Daemon: Start under launchd
    CLI->>Daemon: Store "api-token" over a private local socket
    Daemon->>KC: Save the value
```

| Task | Command |
| --- | --- |
| Install | `brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git` then `brew install veilux-lab/keyward/keyward` |
| Upgrade | `brew upgrade veilux-lab/keyward/keyward` then `keyward service install` |
| Pause access | `keyward service stop` (resume with `keyward service start`) |
| Remove everything | `keyward uninstall` (Keychain items are kept) |

Use `keyward service …` rather than the `brew services` lines Homebrew adds to
every service formula; Keyward's commands also keep first-use startup in step.

## Questions people ask

**Why the "tap is not trusted" warning?** Homebrew 7 refuses third-party formulas
until trusted. Installing by the full name `veilux-lab/keyward/keyward` trusts
only this formula. `brew uninstall` removes that trust, so a reinstall warns again.

**Why does an upgrade ask for Keychain access?** macOS ties Keychain access to the
exact program. Each release is a new program, so macOS may ask once.

**Does it send anything anywhere?** No. Keyward makes no network connections;
Homebrew itself downloads only the release files listed in the formula.

**Why doesn't `brew uninstall` remove everything?** Formulas get no uninstall
hook. `keyward uninstall` removes the daemon, local data, backups, the formula,
and the tap in one step.
