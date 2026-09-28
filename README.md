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

## Usage

```sh
# move the secrets in a shell rc file into the Keychain.
# a dry run is the default: this describes the changes and makes none.
keyward migrate ~/.zshrc
keyward migrate --dry-run ~/.zshrc   # the same thing, said explicitly
keyward migrate -apply ~/.zshrc      # actually make the changes

# store one by hand — piped, so it never appears in argv or shell history
pbpaste | keyward add splunk-mcp-token

keyward ls                      # names only, never values
keyward rm splunk-mcp-token

# run a command with references resolved into its environment
keyward run -- npm test
```

Nothing else changes. `keyward` only touches values beginning with `cap://`;
`PATH`, `EDITOR`, and everything else passes through untouched, so migration is
opt-in per variable.

If a reference cannot be resolved, nothing runs and the error says what to do:

```text
keyward run: 1 reference(s) could not be resolved:
  SPLUNK_MCP_TOKEN=cap://splunk-mcp-token
    keychain get "splunk-mcp-token": secret not found
    add it with: keyward add splunk-mcp-token
```

Starting a command with a literal `cap://` string where a credential belongs would
fail as though the token were wrong rather than missing, so it is refused outright.

Set `KEYWARD_SERVICE` to scope items to a different Keychain service name — useful
for trying it out without touching real entries.

## Status

Working, not yet packaged. There is no installer or Homebrew formula; build it with
`go build ./cmd/keyward`.

Implemented:

- `keyward migrate` — move an rc file's secrets into the Keychain
- `keyward add` / `ls` / `rm` / `run`
- macOS Keychain storage
- reference parsing and environment resolution

Next:

- MCP server config rewriting
- audit log

### On migrate

Dry run by default: it prints what it would change and changes nothing until
`-apply`. `--dry-run` says the same thing explicitly, and combining it with
`-apply` is an error rather than a guess. The diff never shows a value, only its length — printing the old line
verbatim would spill every secret in the file into your scrollback, and into the
context of any agent that ran the command.

Before writing anything it stores each secret, so a failure never leaves the file
pointing at values that are not in the Keychain. The original is copied to a
timestamped backup beside it, the rewrite is atomic, and the file mode is
preserved. Running it twice is safe.

## Development

Requires Go 1.26+ and the Xcode command line tools (for cgo).

```sh
make test
make vet
make cover
```

## License

MIT — see [LICENSE](LICENSE).
