<!-- Written by keyward, which replaces this file when it updates it. Keep your own notes in another file. -->
# Secrets and tokens (keyward)

Credentials in this user's shell files are `cap://name` references. The values are
in keyward's encrypted vault, with its key in the macOS Keychain. A variable holding `cap://…` is a
reference, not a broken value.

- Find a variable's reference with `grep -n 'cap://' ~/.zshrc`, or in the file it
  came from. `keyward ls` lists stored names. Neither shows a value.
- Run a command that needs a credential through keyward, setting the reference
  inline so it does not depend on the shell's startup files, and naming it in
  `--only` so the command gets that secret and no other:
  `GITHUB_TOKEN=cap://github-token keyward run --only GITHUB_TOKEN -- gh pr list`
- Never put a resolved value in another program's arguments: any process can read
  a command line. Expand it inside the child, after resolution, and pass it on
  stdin; `printf` is built into the shell, so it has no command line of its own.
  `"$API_TOKEN"` outside the `sh -c` sends the literal reference:
  `API_TOKEN=cap://api-token keyward run --only API_TOKEN -- sh -c 'printf "header = \"Authorization: Bearer %s\"\n" "$API_TOKEN" | curl -sS -K - "$1"' _ "$URL"`
- Never print a resolved value: no `env`, `printenv`, `echo "$VAR"`, `set -x`, or
  `curl -v` under `keyward run`, and never write one to a file.
- An authentication failure, or a tool that receives `cap://…`, usually means it
  was started outside keyward. Say so rather than looking for the value. For an
  MCP server, `keyward mcp` shows the fix; leave applying it to the user, who can
  run `keyward mcp wrap`.
- If keyward says its daemon is not running, or a Keychain dialog appears, stop and
  tell the user. Do not retry in a loop. If it says the vault key is missing, tell
  the user to run `keyward recovery restore` with their recovery code.
- Do not run `keyward setup`, `migrate`, `restore`, `rm`, `add --force`, `backups
  recover`, `backups rm`, `recovery`, `mcp wrap`, `mcp unwrap`, `agents link`,
  `agents unlink`, or `uninstall`, or read keyward's ledger, backups, or vault,
  unless the user asks.
