# keyward

**Your dotfiles are safe from the internet, not from your AI agents.**

Keyward moves the tokens in `~/.zshrc`, `.env` and similar files into an
encrypted vault, keyed by the macOS Keychain, and leaves a reference behind:

```sh
export API_TOKEN='cap://api-token'
```

Agents reading your files see only the reference. `keyward run` gives the real
value to the one command that needs it.

![How AI agents and MCP servers use keyward](images/agents-and-mcp.png)

## Install

```sh
brew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git   # needed first
brew install veilux-lab/keyward/keyward
keyward setup                                                            # then this, in Terminal.app
```

Apple Silicon only. On Intel, build it with Go: `go build -o keyward ./cmd/keyward`,
then run `./keyward daemon`. To start it at login instead, sign it with a free Apple
Development certificate: `make install SIGN_IDENTITY='Apple Development: …'`.

## Use

```sh
keyward setup                             # guided first run, in Terminal.app; each step asks first
keyward migrate --dry-run ~/.zshrc        # preview; hides values and token-like comments
keyward migrate ~/.zshrc                  # move the secrets; asks for "yes"
keyward run --only API_TOKEN -- npm test  # run a command with the values it names
keyward ls                                # stored names
keyward doctor                            # check your setup
```

- Start anything that needs a secret through `keyward run`; otherwise it sees
  the `cap://` reference. Don't start your editor that way, or everything inside
  it gets the values.
- `keyward run` resolves every reference in its environment. Name just the ones a
  command needs with `--only`: `keyward run --only GITHUB_TOKEN -- gh pr list`.
- Migration keeps an encrypted backup. Remove it with `keyward backups rm ~/.zshrc`
  once everything works.
- `keyward doctor` also finds tokens still in plaintext in your shell files, the
  current folder's `.env`, and MCP configs, and says where each one is without
  printing it. Name another file to check it too: `keyward doctor .env.local`. If
  a line it lists in a shell or `.env` file holds no secret, end it with
  `# keyward:ignore`, and keyward leaves the line alone.
- Keyward writes `~/.agents/keyward.md`, instructions for AI agents; `keyward agents
  link` points your agents at it, and `unlink` reverses that.
- `keyward help` lists every command.

## Save your recovery code

The vault key exists only in your Keychain; if it is lost, so are your secrets.
`keyward setup` and `keyward recovery show` print your recovery code. Run them in
Terminal.app, not an editor's terminal, which AI agents can read, and keep the
code in a password manager. `keyward recovery restore` brings the key back.

## Moving to a new Mac

Your secrets are in two places, and both must reach the new Mac: the vault file,
`~/Library/Application Support/keyward/vault/keyward.vault`, and its key, in the
login Keychain. Apple's Migration Assistant usually copies both with your user
account; other migration tools often copy the files but not the Keychain.

1. On the old Mac, make sure you have the recovery code: run
   `keyward recovery show` in Terminal.app.
2. On the new Mac, copy the vault file over first if it did not come across, then
   install keyward (see [Install](#install)) and run `keyward doctor`. If it says the
   vault opens with its key, you're done; macOS may ask once for Keychain access.
3. If it says the vault key is missing or does not match, run
   `keyward recovery restore` and paste the code.
4. Open a new terminal, and restart your editor and AI tools.

Your rc files, `.env` files, and MCP configs keep their `cap://` references, so they
work again as soon as the vault opens. Without the recovery code and with the old
Mac gone, the secrets cannot be recovered.

## MCP servers

MCP servers that use a migrated token must start through keyward too. `keyward mcp`
prints the fix for each affected server in Claude Code, Codex and Cursor. It
hides literal env and header values, and in its arguments and URL a token with a
known prefix or shaped like a key, user info, query values, header text, and the
value after an option such as `--api-key`; anything else there is printed as
written. `keyward mcp wrap` makes the changes for Claude Code after a
"yes", through its own `claude mcp` command, and `keyward mcp unwrap` starts the
servers without keyward again; restore the files that set their variables first.
Both skip a server that holds a credential in its env or headers, which that
command would get in its command line, until you move it out as `keyward doctor`
says.
For a server of another Claude Code project, run wrap in that project's folder,
which keyward names. A server that reads a variable without naming it in its
config can't be detected; wrap it by hand the same way.

A remote server starts through the mcp-remote bridge, which unwrap leaves in
place. The bridge puts the server's URL in its command line, which any process
can read, and in its log. So wrap will not newly put a migrated token from a
server's URL in a command line unless given `--allow-command-line`, after which
`keyward mcp` and `doctor` list the server as a warning, and doctor reports the
token while the server runs; use header authentication if the server supports it.
They also warn of a server that takes a token as an argument, which stays in its
command line; pass it in env instead if the server reads it from there.

## Uninstall

```sh
keyward uninstall --dry-run   # the full plan; changes nothing
keyward uninstall             # undo everything, after one "yes"; secrets stay in the vault
keyward uninstall --purge     # the same, and delete the vault and its key
```

Uninstall starts Claude Code's MCP servers without keyward again, a remote one
still through its mcp-remote bridge, removes the agent lines keyward added, puts
every value back into its file as it was written, then removes keyward and checks
that nothing is left. It lists anything it cannot change itself, such as
Codex servers. To put one file back without uninstalling: `keyward restore ~/.zshrc`.

Use `keyward uninstall`, not `brew uninstall`: Homebrew removes only the program.
If that happens, the daemon unregisters itself, and reinstalling then running
`keyward uninstall` finishes the job.

## What it protects

Keyward prevents accidental exposure, not deliberate theft: any process running as
you can ask for a value. It makes no network connections and logs names, never
values.

Report vulnerabilities privately ([SECURITY.md](SECURITY.md)). MIT licensed
([LICENSE](LICENSE)).
