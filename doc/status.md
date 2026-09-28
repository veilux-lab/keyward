# Status

Last updated: 2026-09-28

## Where things stand

The reference format and the storage seam are implemented. Nothing is installable
yet: there is no `cmd/` and no real Keychain access.

`make verify` — `go vet`, `gofmt`, and `go test -race`: 19 test functions, 41
subtests, all passing. 100% statement coverage in both `internal/handle` and
`internal/vault`.

## Component status

| Component | State | Notes |
| --- | --- | --- |
| `internal/handle` | **Done** | Parse, `Normalize`, format. Errors proven not to leak their input. |
| `vault.Secret` | **Done** | Redacts through every fmt verb and through JSON. Proven by test. |
| `vault.Store` | **Done** | Interface plus sentinel errors. The seam that keeps everything above it testable. |
| `vault.Memory` | **Done** | In-process fake, concurrency-safe, passes the contract suite under `-race`. |
| `vault/vaulttest` | **Done** | Contract suite. The real Keychain store will be held to exactly this. |
| Keychain store | Not started | **Next.** cgo against `SecItemAdd` / `SecItemCopyMatching`, build-tagged integration test running `vaulttest.Run`. |
| `internal/resolve` | Not started | Unblocked — `vault.Store` exists, so it can be written entirely against `Memory`. |
| `internal/audit` | Not started | Independent; can land any time. |
| `cmd/keyward run` | Not started | Needs resolve. |
| `internal/migrate` | Not started | Needs a real vault. The adoption-critical piece. |
| `internal/mcpconfig` | Not started | Needs `run` to exist and work. |
| `keyward shell` | Not started | Independent of the above. |
| Biometric gating | Not started | Feasibility unconfirmed — see [obstacles.md](obstacles.md). |

## What gates what

Not a schedule. A dependency order, so it is always clear what is actually
available to work on.

**Nothing gates these:**

- **Keychain store** — the cgo implementation behind `vault.Store`. Verified by
  running `vaulttest.Run` against it under a build tag.
- `internal/resolve` — environment scanning and reference resolution. Unblocked
  now that `vault.Store` and `vault.Memory` exist; needs no real Keychain.
- `internal/audit` — append-only JSONL. No dependencies.

**Gated on the Keychain store and resolve:**

- `cmd/keyward run` — resolve plus `syscall.Exec`. Needs a real vault to be
  useful, though it can be exercised against `Memory` first.

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

**2026-09-28** — `vault.Secret`, `vault.Store`, and `vault.Memory` implemented
test-first, plus the `vaulttest` contract suite that the real Keychain store will
also have to pass. `handle.Normalize` extracted so the vault and the reference
parser share one definition of a valid name. MIT licensed. `make verify` added.

**2026-09-27** — Repository created. `internal/handle` implemented test-first.
Design, mission, obstacles, and landscape documented. Scope narrowed from a
general secrets broker to the shell-rc problem specifically.
