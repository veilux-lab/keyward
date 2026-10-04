# keyward docs

| Document | What it covers |
| --- | --- |
| [install.md](install.md) | Everyday commands, migration, restoration, signed local setup, and logs |
| [homebrew.md](homebrew.md) | Homebrew setup, upgrades, switching taps, and releases |
| [mission.md](mission.md) | The problem, the invariant, and what keyward deliberately is not |
| [design.md](design.md) | Architecture, reference format, trust model, and the reasoning behind each decision |
| [status.md](status.md) | Current state, component status, dependency order, and the go/no-go test |
| [obstacles.md](obstacles.md) | Known problems and complexities, including one that already invalidated a design |
| [landscape.md](landscape.md) | Prior art, what it does better, and where keyward actually stands |
| [handoff-apple-development-signing.md](handoff-apple-development-signing.md) | Instructions for an agent testing free Apple Development signing on a personal Mac |

## Visual walkthrough

[architecture.html](architecture.html) — 19 slides covering the problem, the
architecture, the resolution pipeline, and the register of known obstacles. A
single self-contained file with no dependencies; open it in a browser directly.

Arrow keys, space, or scroll to navigate. Press `E` or hover the top-left corner
to edit text in place; edits persist to `localStorage`, and `Cmd+S` downloads the
modified file.

Built with the [frontend-slides](https://github.com/zarazhangrui/frontend-slides)
skill. Slides are authored on a fixed 1920×1080 stage that scales as a whole, so
the layout is identical on every screen rather than reflowing. Verified with a
headless browser for content overflow and panel overlap at 1920×1080, 1280×720,
and a phone viewport — `scrollHeight` checks alone miss panels that visually
cover each other.

## Keeping these current

`status.md` is the only file expected to change often — update its changelog and
component table as components land. `obstacles.md` should grow whenever something
turns out harder than expected, and shrink only when a problem is genuinely
solved rather than forgotten.
