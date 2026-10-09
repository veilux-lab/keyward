<!-- Written by keyward, which replaces this file when it updates it. Keep your own notes in another file. -->
# Secrets and tokens (keyward)

Credentials in this user's shell files are `cap://name` references. The values are
in keyward's encrypted vault, with its key in the macOS Keychain. A variable holding `cap://…` is a
reference, not a broken value.

- Find a variable's reference with `grep -n 'cap://' ~/.zshrc`, or in the file it
  came from. `keyward ls` lists stored names. Neither shows a value.
- Run a command that needs a credential through keyward, setting the reference
  inline so it does not depend on the shell's startup files:
  `GITHUB_TOKEN=cap://github-token keyward run -- gh pr list`
- When the value is part of an argument, expand it inside the child, after
  resolution. `"$API_TOKEN"` outside the `sh -c` sends the literal reference:
  `API_TOKEN=cap://api-token keyward run -- sh -c 'curl -sS -H "Authorization: Bearer $API_TOKEN" "$1"' _ "$URL"`
- Never print a resolved value: no `env`, `printenv`, `echo "$VAR"`, `set -x`, or
  `curl -v` under `keyward run`, and never write one to a file.
- An authentication failure, or a tool that receives `cap://…`, usually means it
  was started outside keyward. Say so rather than looking for the value.
- If keyward says its daemon is not running, or a Keychain dialog appears, stop and
  tell the user. Do not retry in a loop.
- Do not run `keyward migrate`, `restore`, `rm`, `add --force`, `backups recover`,
  `backups rm`, or `uninstall`, or read keyward's backups, unless the user asks.
