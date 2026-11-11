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

## MCP servers

An MCP server that uses a migrated token must start through `keyward run`.
`keyward mcp` prints the fix for each affected server in Claude Code, Codex and
Cursor. It hides literal env and header values, and in its arguments and URL a
token with a known prefix or shaped like a key, user info, query values, header
text, and the value after an option such as `--api-key`; anything else there is
printed as written.

`keyward mcp wrap` makes the changes for Claude Code after a "yes", through its
own `claude mcp` command, and `keyward mcp unwrap` starts the servers without
keyward again; restore the files that set their variables first. Both skip a
server that holds a credential in its env or headers, since `claude mcp` would get
it in its command line. Move it out as `keyward doctor` says, then run the command
again.

For a server of another Claude Code project, run wrap in that project's folder,
which keyward names. A server that reads a variable without naming it in its
config can't be detected; wrap it by hand the same way.

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
`keyward mcp wrap`, which makes the fixes for Claude Code. For Codex and Cursor,
make the edits it prints by hand. `keyward mcp` reads a Cursor project's servers
only in the folder it runs in and in those of Claude Code's projects, so run it in
each other folder you open in Cursor too. It does not check a server of another
client, or one that starts `keyward run` in a way it cannot read, as from a script
file: start such a server once to see that it still runs.

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
