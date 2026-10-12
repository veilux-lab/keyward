#!/bin/bash
set -euo pipefail

formula=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "${1:?usage: update-homebrew.sh formula}")
directory=$(mktemp -d "${TMPDIR:-/tmp}/keyward-formula.XXXXXX")
worktree="$directory/source"
cleanup() {
  git worktree remove --force "$worktree" >/dev/null 2>&1 || true
  rm -rf "$directory"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for attempt in 1 2 3; do
  git fetch --no-tags origin main
  git worktree add --detach "$worktree" FETCH_HEAD
  decision=$(python3 - "$worktree/Formula/keyward.rb" "$formula" <<'PY'
from pathlib import Path
import re
import sys

current, candidate = (Path(path).read_text() for path in sys.argv[1:])
def version(formula):
    match = re.search(r'^\s*version "([0-9]+)\.([0-9]+)\.([0-9]+)"$', formula, re.MULTILINE)
    if not match:
        sys.exit("Missing stable Homebrew version")
    return tuple(map(int, match.groups()))
old, new = version(current), version(candidate)
if new == old and current != candidate:
    sys.exit("Refusing to replace a formula checksum at the same version")
print("update" if new > old else "unchanged")
PY
  )
  if [ "$decision" = unchanged ]; then
    echo "Homebrew already has this or a newer release"
    exit 0
  fi
  cp "$formula" "$worktree/Formula/keyward.rb"
  make -C "$worktree" verify
  git -C "$worktree" add Formula/keyward.rb
  git -C "$worktree" -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' commit -m 'Update Homebrew to the published release'
  if git -C "$worktree" push origin HEAD:refs/heads/main; then
    exit 0
  fi
  git worktree remove --force "$worktree"
done
echo "Homebrew formula update failed after three fast-forward attempts" >&2
exit 1
