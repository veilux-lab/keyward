# keyward in detail

The [README](../README.md) covers everyday use. This page has the details behind it.

## Building from source

On Intel, build keyward with Go: `go build -o keyward ./cmd/keyward`, then run
`./keyward daemon`. To start it at login instead, sign it with a free Apple
Development certificate: `make install SIGN_IDENTITY='Apple Development: …'`.

## Masking

When a command's output goes to an agent, a pipe or a file rather than a terminal,
`keyward run` shows `cap://name#masked` in place of each value it gave the
command, also when the value is JSON-, URL- or base64-encoded (base64 only on one
line), and says so.

- A multi-line value, such as a private key or a credentials file, is hidden only
  when the command prints it whole, as stored or in one of those encodings; a line
  of it printed on its own, or the value re-indented, is not, though output that
  ends or pauses right after its first lines can show the placeholder in their
  place.
- Masking misses values under 8 characters or also in another environment
  variable, part of a value, such as `${TOKEN:0:8}`, a value quoted for a shell or
  HTML, and output that goes straight to a terminal, such as an agent tool's own
  terminal. It does not cover what a command writes to its own files or sends over
  the network.

## When masking gets in the way

- `--no-mask` turns masking off. Masking gives the command a pipe in place of a
  file you redirect its output to, so for a tool that needs to seek in its output,
  like `pg_dump -Fc`, use `--no-mask` or put the redirect inside the command:
  `keyward run --only PGPASSWORD -- sh -c 'pg_dump -Fc db > db.dump'`.
- If the output's destination fails, as on a full disk, the command's next write
  fails, which ends most commands, and `keyward run` exits 1, or with the
  command's own failure code, saying why; to keep a long-running process going,
  redirect inside the command too.
- A command that moves to a process group of its own, as `timeout` does, cannot
  read from the terminal while masked: use `timeout --foreground`.
- A SIGINT or SIGQUIT that pexpect, node-pty or a shell in another terminal sends
  to a masked `keyward run` in a terminal's foreground does not reach the command:
  send SIGTERM instead, or use `--no-mask`. A SIGTSTP sent to a masked
  `keyward run` alone, not to its process group as a terminal sends it, stops
  `keyward run` but not the command.
- Masked, `keyward run` also waits for anything the command leaves running with
  its output, like the server in `sh -c 'server &'`. Once `keyward run` is
  stopped, the server's later output is lost, and most servers die at their next
  write, but some, like those using Python's logging, run on: stop it with kill.
  Redirect the job's output inside the command, `sh -c 'server > server.log 2>&1 &'`,
  run all of `keyward run` in the background instead, or use `--no-mask`.

## The command-line check

The check that keeps values out of command lines reads only a script given to
`sh`, `bash`, `dash` or `zsh` with `-c`, also when another program starts the
shell, as in `time sh -c` or `find -exec sh -c`. If it cannot read a script, as
with some of zsh's syntax, or follow it to its end, as with one too long or
complex, it refuses the script if the script names a variable `keyward run`
resolves, and otherwise lets it run unchecked.

A value can still reach a command line through:

- a script a shell reads from a file, a pipe or `keyward run`'s own stdin, as in
  `sh f`, `source f`, `cat f | sh` or `keyward run -- bash <<'EOF'`, or code made
  as the script runs, as for `eval "$(cat f)"`;
- code that `python -c` or `node -e` runs;
- a tool that puts its environment in its children's arguments, such as
  `env -S`, `make`, `npm run` or `docker compose`;
- a file the script writes it to and reads back;
- startup files and exported functions that redefine a builtin, such as
  `BASH_ENV`, `BASH_FUNC_*` and `~/.zshenv`.

Nor does the check follow output a script sends through a descriptor other than 1
or 2, as with `>&3`, an alias the script defines again, zsh's global aliases, or
what `trap` code writes.

## Bindings

`--only` limits which secrets a command gets, but nothing limits where a secret
goes once a command has it. A binding does: it names the programs a secret may
reach, and `keyward run` enforces it.

Bind a secret with `keyward bind NAME --program gh`, repeating `--program` for
more than one. `keyward unbind NAME --program gh`, or `--all`, removes bindings,
and `keyward bindings` lists them without values. Changing a binding needs a
typed "yes" in a terminal, which keeps a pipe or an agent's ordinary command from
changing it, though not a program that runs keyward in a pseudo-terminal; the
agent guide tells agents never to run `bind` or `unbind`.

`keyward run` gives a bound secret only to a program it starts directly whose
path the secret is bound to:

- The program is matched by the absolute path your `PATH` finds when you bind it,
  without following symlinks. A fake `gh` earlier on `PATH` does not match
  `/opt/homebrew/bin/gh`, and matching the path rather than the Cellar target
  keeps the binding working across Homebrew upgrades.
- A `sh -c` script never gets a bound secret, whatever programs it names, even
  when the shell itself is bound. The shell can pass the value on with built-ins
  alone, as a redirect to `/dev/tcp` does, and a script can make a program's name
  run something else, by changing `PATH` or defining a function. A launcher such
  as `env`, `sudo` or `xargs` is the program `keyward run` starts, so it does not
  get the secret either.
- A program started with a `DYLD_` variable set, such as `DYLD_INSERT_LIBRARIES`,
  does not get a bound secret, even the program it is bound to: the variable
  makes it load other code, which would get the secret with it.
- A bound secret named in `--only` that the command may not have is refused,
  naming the secret and where it may go. One not named in `--only` is left as its
  `cap://` reference, which `keyward run` says in one line, so
  `keyward run -- npm test` keeps working when an unrelated bound secret is in
  the environment.

So start the bound program itself, one call per `keyward run`, with loops, pipes
and redirects outside it; output that reaches a pipe or a file is still masked.
For a tool that seeks in its output, use its own output option, as
`pg_dump -Fc -f db.dump db`. curl 8.3 or later can read a value itself, with no
script:
`keyward run --only API_TOKEN -- curl -sS --variable %API_TOKEN --expand-header 'Authorization: Bearer {{API_TOKEN}}' URL`.

Bind a token to the program that uses it, but know that the bound program
still passes it to whatever it runs: `gh` to the browser, pager and editor its
settings or environment name, and to its aliases and extensions; curl, a shell,
an interpreter such as `python3`, `npx` or a launcher can send it anywhere. So a
binding catches mistakes, such as a script that sends a token to the wrong
place, not an agent set on getting around it.

An MCP server that gets a secret through `keyward run` stops starting once the
secret is bound, unless `keyward run` starts the server as a bound program.
`keyward bind` and `keyward unbind` name such servers before they ask, and
`keyward mcp` does not check bindings, so give each such server a secret of its
own first.

A binding is part of the value's seal: the associated data that AES-GCM
authenticates is the secret's name together with its canonical bindings. Editing
or removing a binding in the vault file by hand therefore makes the value fail to
decrypt, rather than quietly unbinding it. The vault file stays version 1 until
the first binding is set and returns to version 1 when the last is removed, so an
older keyward still reads a vault with no bindings. A binding of a kind this
keyward does not understand, written by a later version, allows no program.

This stops a mistaken `keyward run` from handing a secret to the wrong program.
It does not stop a program the secret is bound to from doing what it likes with
it, or being told to by its settings, nor malware running as you, which can
replace a bound program, as Homebrew's folders are writable by you, or ask the
daemon for a value directly.

## MCP servers

An MCP server that uses a migrated token must start through `keyward run`.
`keyward mcp` prints the fix for each affected server in Claude Code, Codex,
Cursor and Copilot CLI. It hides literal env and header values, and in its
arguments and URL a token with a known prefix or shaped like a key, user info,
query values, header text, and the value after an option such as `--api-key`;
anything else there is printed as written.

`keyward mcp wrap` makes the changes for Claude Code after a "yes", through its
own `claude mcp` command, and `keyward mcp unwrap` starts the servers without
keyward again; restore the files that set their variables first. Both skip a
server that holds a credential in its env, headers or another setting, since
`claude mcp` would get it in its command line. Move it out as `keyward doctor`
says, then run the command again.

For a server of another Claude Code project, run wrap in that project's folder,
which keyward names. A server that reads a variable without naming it in its
config can't be detected; wrap it by hand the same way.

### Copilot CLI

Copilot CLI starts the servers in `~/.copilot/mcp-config.json` and in a project's
`.mcp.json`, which Claude Code starts too, or without one, its `.github/mcp.json`.
Once Copilot is installed, `keyward mcp` checks a `.mcp.json` server by the rules
of both.

Copilot fills in `$VAR` and `${VAR}` in a server's command itself, from its own
environment, before `keyward run` or a shell sees them, even in single quotes: a
migrated variable as its `cap://` text, and `GITHUB_TOKEN`, migrated or not, as
Copilot's own GitHub token, which is then in a command line. A name its
environment lacks, as one only the server's env sets, stays as written. So
`keyward mcp` leaves a server whose command would read a migrated variable or
`GITHUB_TOKEN` for you to change: set the variable the server reads to its
`cap://` reference in env, or have a script that reads the value itself read a
name only env sets. The `'$''{VAR}'` spelling keyward writes in an mcp-remote
header passes through unchanged.

Copilot also passes a server no `GITHUB_TOKEN`, and leaves `${GITHUB_TOKEN}` in
env as written. So the fix sets its reference in the server's env, and for a
server that already runs through `keyward run` and would not get it,
`keyward mcp` prints that change. A server that reads `GITHUB_TOKEN` unmigrated
in an mcp-remote header, which Copilot fills with its own token, is left for you
to change too, as mcp-remote would have no token to fill it with.

### Remote servers

A remote server starts through the mcp-remote bridge, which unwrap leaves in
place. The bridge puts the server's URL in its command line, which any process
can read, and in its log. `keyward run` refuses to start a server whose URL holds
a migrated token, or that passes one to its program as an argument. `keyward mcp`
says why, as `keyward run` does, with the fix: header authentication if the
server supports it, or the token in env if the server reads it from there.
`keyward mcp wrap` skips such a server unless given `--allow-command-line`, which
it also writes into the server's `keyward run`; a bridge an earlier keyward wrote
it rewrites as before, saying if `keyward run` still refuses it. `keyward mcp` and
`doctor` then list an allowed server as a warning, and doctor reports the token
while the server runs.

### Upgrading from 1.4 or earlier

Run `keyward mcp`: it lists each server `keyward run` now refuses to start, with
the fix. A server you wrapped with `--allow-command-line` before needs only
`keyward mcp wrap`, which makes the fixes for Claude Code. For Codex, Cursor and
Copilot CLI, make the edits it prints by hand. `keyward mcp` reads a Cursor or
Copilot CLI project's servers only in the folder it runs in and in those of
Claude Code's projects, so run it in each other folder you open in Cursor or
Copilot CLI too. It does not check a server of another client, or one that starts
`keyward run` in a way it cannot read, as from a script file: start such a server
once to see that it still runs.

## Agents' own files

`keyward doctor` reads the files AI agents keep for themselves, which any agent
can read and a repository can publish, in home, the current folder and each
Claude Code project in `~/.claude.json`. It lists those it read but those of
other projects, which it counts.

- Claude Code's settings: `.claude/settings.json` and `.claude/settings.local.json`,
  in home and in a project. Claude Code saves a project's local settings at the
  root of its git repository, a worktree's in its main checkout, and doctor reads
  them there too.
- Codex's `~/.codex/config.toml` beside its MCP servers, as its OpenTelemetry and
  model providers' headers.
- Instructions: `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`,
  `~/.codex/AGENTS.override.md`, `~/.copilot/copilot-instructions.md` and
  `~/.gemini/GEMINI.md`, and in a project `CLAUDE.md`, `.claude/CLAUDE.md`,
  `CLAUDE.local.md`, `AGENTS.md`, `AGENTS.override.md` and
  `.github/copilot-instructions.md`. Only what is surely a credential counts
  there, in a line or set as a shell, YAML or JSON sets one: not an example, as
  `user:password@` and `sk-ant-api03-xxxx` are, nor the login a local database
  is set up with, as `postgres:postgres@localhost` is.

When you answer "Yes, and don't ask again", Claude Code saves the approved
command, or the prefix the prompt names, as an allow rule; text before that
point, such as `PGPASSWORD=…`, is saved with it. It saves the rule in the
project's `.claude/settings.local.json`, or where VS Code's approval card says,
which can be the shared `.claude/settings.json`. So doctor reads each rule's
command for a password: in a URL, after `Bearer`, in a variable or curl header
named like a credential, or given to `mysql -p`, `sshpass -p` or `curl -u`.
Remove a rule with `/permissions` in Claude Code; a command that reads the
secret through `keyward run` saves none.

Claude Code resolves no reference in a settings file's `env`. Its own variables,
such as `ANTHROPIC_API_KEY`, come out, or move to the helper setting doctor names,
as `apiKeyHelper`; a helper that reads a value through `keyward run` needs
`--no-mask`. Doctor lists such a credential, and one in Codex's OpenTelemetry
headers, as a warning rather than a problem, since keyward has no way to hold it
there. A variable only the commands it starts need can hold `cap://NAME`,
which a command started through `keyward run` resolves. `keyward uninstall`
cannot change it back, so it lists the file, and `--purge` waits until you
change it. Such a reference must resolve, but one in instructions or a rule is
an example, or a command an agent may run, so it only counts as in use.

doctor also asks git whether it tracks a personal file: `.claude/settings.local.json`,
`CLAUDE.local.md`, or an agent's login in home, `~/.claude/.credentials.json` or
`~/.codex/auth.json`, which doctor never reads. The global git excludes Claude
Code writes for its local settings do not travel with a clone. Where git cannot
read a repository, doctor does not say that none is tracked, and it does not see
a home tracked through a bare repository.

It does not yet read Codex's saved approvals in `~/.codex/rules/`, its profile
files, a project's `.codex/config.toml`, or rules files under `.claude/rules/` and
`.github/instructions/`.

## Moving to a new Mac

Your secrets are in two places, and both must reach the new Mac: the vault file,
`~/Library/Application Support/keyward/vault/keyward.vault`, and its key, in the
login Keychain. Apple's Migration Assistant usually copies both with your user
account; other migration tools often copy the files but not the Keychain.

1. On the old Mac, make sure you have the recovery code: run
   `keyward recovery show` in Terminal.app.
2. On the new Mac, copy the vault file over first if it did not come across, then
   install keyward (see the [README](../README.md#install)) and run
   `keyward doctor`. If it says the vault opens with its key, you're done; macOS
   may ask once for Keychain access.
3. If it says the vault key is missing or does not match, run
   `keyward recovery restore` and paste the code.
4. Open a new terminal, and restart your editor and AI tools.

Your rc files, `.env` files, and MCP configs keep their `cap://` references, so they
work again as soon as the vault opens. Without the recovery code and with the old
Mac gone, the secrets cannot be recovered.

## Uninstall

Uninstall starts Claude Code's MCP servers without keyward again, a remote one
still through its mcp-remote bridge, removes the agent lines keyward added, puts
every value back into its file as it was written, then removes keyward and checks
that nothing is left. It lists anything it cannot change itself, such as Codex
servers.

If `brew uninstall` removed the program first, the daemon unregisters itself, and
reinstalling then running `keyward uninstall` finishes the job.
