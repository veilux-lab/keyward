# Status

Last updated: 2026-09-27

## Where things stand

One commit. The reference format is specified and implemented; nothing is
installable yet.

```
dd7d9a2  Add reference parsing for keyward
```

`make test`: 7 test functions, 29 subtests, all passing. `go vet` and `gofmt`
clean.

## Component status

| Component | State | Notes |
| --- | --- | --- |
| `internal/handle` | **Done** | Parse, validate, format. Errors proven not to leak their input. |
| `internal/vault` | Not started | Next. cgo against Security.framework. |
| `internal/resolve` | Not started | Needs `vault.Store`. |
| `cmd/keyward run` | Not started | Needs resolve. |
| `internal/migrate` | Not started | Needs vault. The adoption-critical piece. |
| `internal/mcpconfig` | Not started | Needs `run` to exist and work. |
| `internal/audit` | Not started | Independent; can land any time. |
| `keyward shell` | Not started | Independent of the above. |
| Biometric gating | Not started | Feasibility unconfirmed — see [obstacles.md](obstacles.md). |

## What gates what

Not a schedule. A dependency order, so it is always clear what is actually
available to work on.

**Nothing gates these:**

- `internal/vault` — the `Store` interface, the in-memory fake, and the cgo
  implementation behind it.
- `internal/audit` — append-only JSONL. No dependencies.

**Gated on `vault.Store` existing:**

- `internal/resolve` — environment scanning and reference resolution, tested
  entirely against the fake.
- `cmd/keyward run` — resolve plus `syscall.Exec`.

**Gated on `keyward run` working end to end:**

- `internal/migrate` — rewrite `~/.zshrc`, values into the Keychain. Dry-run by
  default, diff shown, backup kept.
- `internal/mcpconfig` — rewrite MCP server configs. Delivers the
  Finder-launch fix.

**Gated on the migration being lived with:**

Everything else. `shell`, grants, approval queue, MCP tool surface. Building
these before the core is in daily use would be building on a guess.

**Gated on the cgo vault being solid:**

- Biometric gating. It is the one genuine differentiator, and also the piece most
  likely to turn out infeasible. Attempting it early would risk the whole project
  on its hardest unknown.

## The decision point

The project has one real go/no-go, and it is not about security:

> Migrate `~/.zshrc` and one project's `.env`, then work normally. If
> `keyward run --` is not close to invisible across `docker compose`, `phpunit`,
> and editor run configurations, stop.

Friction is the thing that kills tools like this, not weak guarantees. This test
runs as soon as `migrate` lands and needs no further machinery. If it fails, the
correct response is to stop building, not to push through.

## Changelog

**2026-09-27** — Repository created. `internal/handle` implemented test-first.
Design, mission, obstacles, and landscape documented. Scope narrowed from a
general secrets broker to the shell-rc problem specifically.
