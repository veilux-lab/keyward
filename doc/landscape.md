# Landscape

Researched 2026-09-25 and 2026-09-27. Recorded so the same ground is not
re-covered, and so the project's actual position stays honest.

## The nearest thing: HASP

[gethasp/hasp](https://github.com/gethasp/hasp) — "a local secret broker for
coding agents." Go, ~360 stars, created April 2026, actively developed, Homebrew
with signed releases, **Fair Core License** (source-available, not open source,
which signals commercial intent).

Its stated core rule is *"Managed secret values must not enter agent context"* —
the same invariant keyward holds. It arrived independently at nearly the same
architecture: a vault, references and aliases, a value-free manifest, grants
scoped by actor and project and action and time, brokered execution, an MCP path
for agents, an audit log, repo hooks blocking managed values from commits, and
redaction explicitly demoted to "a backup guard, not the main design."

Seven agent profiles ship with it, including Claude Code, Codex CLI, and Cursor.

### What it does better

- **Project binding** as an explicit repo boundary, so a value imported for one
  project cannot leak into another on the same machine. keyward has no answer to
  this yet.
- **`inject`** for file-shaped credentials, not just environment variables.
- **The escalation ladder** — `run` → `inject` → `write-env` → `reveal` — with
  each step documented as trading safety for convenience. Adopted; see
  [design.md](design.md).

### Where it leaves room

- **Its model is project-scoped.** Project bindings, `.hasp.manifest.json`,
  per-repo targets. A shell rc file is not in a repo, so the specific problem
  keyward exists to solve sits outside that architecture.
- **Fair Core licensing.** A real adoption barrier for a security tool, where
  being able to read and fork the thing is part of the trust story.
- **No biometric gating.** Its dependency list is `creack/pty`,
  `golang.org/x/crypto`, `golang.org/x/sys` — a hand-rolled encrypted vault for
  Linux portability, with no Keychain or Secure Enclave involvement.

That last point is the whole reason keyward can be macOS-only and better for it:
no custom cryptography, OS-provided per-item ACLs, and access-control flags
available.

## Agent firewalls — a different problem, already taken

Do not build one.

**Pipelock** ([luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock),
pipelab.org) — Apache 2.0, Go, ~900 stars in seven months, CNCF Landscape, 17
agent integrations, 65 DLP patterns, Ed25519-signed receipts, enterprise tier.
Linux via Landlock and seccomp, macOS via `sandbox-exec`. Egress-first: its
filesystem component watches for secrets *written* to disk, not read.

**Coder Agent Firewall** / [coder/boundary](https://github.com/coder/boundary) —
MIT CLI, network only, **Linux only** (macOS explicitly unsupported), and the
product requires a Premium license. nsjail by default, or Landlock V4.

Both are egress control. Neither does read-side elimination. They are
complementary to keyward, not competitive with it — obstacle 7 in
[obstacles.md](obstacles.md) is precisely the gap a tool like Pipelock fills.

## Secret managers — the primitive is mature

**1Password** `op://` references with `op run` already do reference-at-rest and
exec-time resolution, and the references are safe to commit. This is the same
mechanism keyward uses; there is no point inventing a competing format, and
supporting `op://` and `vault://` as backends would be a compatibility win rather
than a compromise.

What it lacks, and what nobody in this space provides:

- No audit trail of **which caller** resolved which secret.
- No scoping of resolution to specific commands or callers.

Per-caller attribution — which agent, which session, which request — is the one
genuinely unoccupied position, and the part a team would eventually pay for.

**Vault, Infisical, Doppler** occupy the same ground: secret references plus
injection, built for services rather than a developer's laptop, with no
agent-specific layer.

## MCP's own answer

The MCP authorization specification is explicit that stdio transports **"SHOULD
NOT"** follow its OAuth flow and should "instead retrieve credentials from the
environment." Remote HTTP MCP servers get OAuth 2.1 with audience-bound
short-lived tokens; local stdio servers get environment variables.

So the ecosystem has standardised on exactly the pattern that puts plaintext
tokens in config files. A broker that injects references at MCP server launch is
working *with* the specification, not against it — and local stdio MCP servers are
the clearest unaddressed surface in the whole picture.

## Position

keyward is a follower in the category and the leader in one narrow spot:
machine-level secrets on macOS, with the Keychain rather than a custom vault, and
with biometric gating as the unclaimed differentiator if it proves feasible.

It is a personal tool whose first job is to fix one daily annoyance. That is
sufficient justification on its own, and it is a more honest basis than a market
claim the research does not support.
