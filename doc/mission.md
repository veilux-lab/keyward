# Mission

## The frustration this exists to fix

An agent reads `~/.zshrc`. Usually for a completely ordinary reason — checking
`PATH`, working out why a variable is unset, looking at an alias. In doing so it
pulls every exported token into its context window, and from there into a
transcript that may be stored, replayed, or summarised somewhere else.

Nothing malicious happened. Nobody made a mistake worth calling a mistake. The
tokens leaked anyway, and they will leak again tomorrow, because the file is
readable and reading it is a reasonable thing to do.

That is the problem. Not a hypothetical attacker — the ordinary operation of a
helpful tool.

## What keyward is

A local secrets broker for a macOS developer machine. Secret values live in an
encrypted vault whose key the macOS Keychain holds. The files that used to hold
them hold references instead:

```sh
export SPLUNK_MCP_TOKEN='cap://splunk-mcp-token'
```

Commands that genuinely need a value get it at execution time. Anything reading
the file, or running `env`, sees a reference.

## The invariant

> A secret value is never present in plaintext on disk, and never enters an
> agent's context.

This is deliberately narrower than "agents cannot access secrets." See
[obstacles.md](obstacles.md) for why the broader claim would be false.

## Why references rather than blocking reads

Blocking file reads means wrapping the agent — a sandbox around every agent you
run, changed for each new one, maintained forever. That is a tax on the user and
a per-vendor integration burden on the tool. Most people will not pay it, which
means the tool does not get adopted, which means it protects nobody.

References invert this. There is no plaintext to find, so there is nothing to
enforce. keyward asks nothing of the agent and needs no knowledge of which agent
is running. It works with agents that do not exist yet, with GUI and cloud
agents, and with agents whose permission systems it has never heard of.

Cooperation then governs *productivity* — whether an agent thrashes or works
smoothly — not *security*. Those are separable concerns and only one of them
needs the agent's goodwill.

## Non-goals

- **Not an agent firewall.** Network egress control is a solved and crowded
  space. See [landscape.md](landscape.md).
- **Not enforcement.** No sandbox, no wrapper, no interception of reads.
- **Not a defence against a determined agent.** An agent that can run commands
  can run a resolver. keyward closes the accidental case, which is the large
  majority of real exposure, and says so plainly rather than overselling.
- **Not cross-platform.** macOS only, so the Keychain can be used instead of
  hand-rolled cryptography.
- **Not a team product.** A personal tool first. If it turns out to be useful to
  others, that is a later question.

## Who it is for

Initially one person, on one machine, with tokens in a shell rc file and several
MCP servers that read them. Every design decision should be checked against
whether it makes that machine better, not against an imagined enterprise buyer.
