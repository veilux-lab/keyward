# keyward

Keeps secrets out of what AI coding agents can read.

Agents read your shell rc file. Usually for ordinary reasons — checking `PATH`,
tracing why a variable is unset — and in doing so they pull every exported token
into their context. Nothing malicious happened, and the tokens are now in a
transcript.

keyward replaces those values with references:

```sh
# before
export SPLUNK_MCP_TOKEN=eyJraWQ...

# after
export SPLUNK_MCP_TOKEN='cap://splunk-mcp-token'
```

The value moves into the macOS Keychain. An agent reading `~/.zshrc`, or running
`env`, sees a reference. Commands that need the real value get it at execution
time:

```sh
keyward run -- npm test
```

## Why references instead of blocking reads

Blocking file reads means wrapping every agent, which means changing how you
launch each one, for every agent you use now and later. keyward asks nothing of
the agent: there is no plaintext to find, so nothing needs to be enforced.

This closes the accidental case, which is most of the real risk. It does not stop
an agent that deliberately sets out to obtain a credential — any process that can
run commands can run the resolver. Tools that claim otherwise on a developer
machine are usually overselling.

## Status

Early. Nothing is installable yet.

Implemented:

- `internal/handle` — reference parsing and validation

Next:

- Keychain vault (cgo, Security.framework)
- `keyward run` — resolve references into a child process environment
- `keyward migrate` — rewrite an rc file, moving values into the Keychain
- MCP server config rewriting

## Development

Requires Go 1.26+ and the Xcode command line tools (for cgo).

```sh
make test
make vet
make cover
```

## License

MIT — see [LICENSE](LICENSE).
