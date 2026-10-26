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
keyward setup                                                            # then this
```

Apple Silicon only. On Intel, build it with Go: `go build -o keyward ./cmd/keyward`,
then run `./keyward daemon`. To start it at login instead, sign it with a free Apple
Development certificate: `make install SIGN_IDENTITY='Apple Development: …'`.

## Use

```sh
keyward setup                        # guided first run: each step asks first
keyward migrate --dry-run ~/.zshrc   # preview; values are never printed
keyward migrate ~/.zshrc             # move the secrets; asks for "yes"
keyward run -- npm test              # run a command with the real values
keyward ls                           # stored names
keyward doctor                       # check your setup
```

- Start anything that needs a secret through `keyward run --`; otherwise it sees
  the `cap://` reference. Don't start your editor that way, or everything inside
  it gets the values.
- `keyward run` resolves every reference in its environment. Name just the ones a
  command needs with `--only`: `keyward run --only GITHUB_TOKEN -- gh pr list`.
- Migration keeps an encrypted backup. Remove it with `keyward backups rm ~/.zshrc`
  once everything works.
- Keyward writes `~/.agents/keyward.md`, instructions for AI agents; `keyward agents
  link` points your agents at it, and `unlink` reverses that.
- `keyward help` lists every command.

## Save your recovery code

The vault key exists only in your Keychain; if it is lost, so are your secrets.
Run `keyward recovery show` once in a terminal and keep the code in a password
manager. `keyward recovery restore` brings the key back.

## Moving to a new Mac

Your secrets are in two places, and both must reach the new Mac: the vault file,
`~/Library/Application Support/keyward/vault/keyward.vault`, and its key, in the
login Keychain. Apple's Migration Assistant usually copies both with your user
account; other migration tools often copy the files but not the Keychain.

1. On the old Mac, make sure you have the recovery code: `keyward recovery show`.
2. On the new Mac, install keyward (see [Install](#install)), then run `keyward ls`.
   If it lists your secrets, you're done; macOS may ask once for Keychain access.
3. If it says the vault key is missing, run `keyward recovery restore` and paste the
   code. If the vault file is missing too, copy it over from the old Mac first.
4. Open a new terminal, and restart your editor and AI tools.

Your rc files, `.env` files, and MCP configs keep their `cap://` references, so they
work again as soon as the vault opens. Without the recovery code and with the old
Mac gone, the secrets cannot be recovered.

## MCP servers

MCP servers that use a migrated token must start through keyward too. `keyward mcp`
prints the fixed definition for each affected server in Claude Code, Codex and
Cursor; `keyward mcp wrap` makes the changes for Claude Code after a "yes", through
its own `claude mcp` command, and `keyward mcp unwrap` reverses them. A server
that reads a variable without naming it in its config can't be detected; wrap it
by hand the same way.

## Uninstall

```sh
keyward uninstall --dry-run   # the full plan; changes nothing
keyward uninstall             # undo everything, after one "yes"; secrets stay in the vault
keyward uninstall --purge     # the same, and delete the vault and its key
```

Uninstall changes Claude Code's MCP servers back, removes the agent lines keyward
added, puts every value back into its file as it was written, then removes keyward
and checks that nothing is left. It lists anything it cannot change itself, such as
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
