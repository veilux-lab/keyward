#!/bin/bash
# Zero-residue test: install this checkout through Homebrew, use it, uninstall
# with --purge, and require every place keyward writes to look as it did before.
# Run it on a disposable Mac or CI runner; it refuses if keyward is already there.
set -euo pipefail
cd "$(dirname "$0")/.."

support="$HOME/Library/Application Support"
if brew tap | grep -qx veilux-lab/keyward || [ -e "$support/keyward" ] || [ -e "$support/keyward-vault" ] ||
   /usr/bin/security find-generic-password -s keyward-vault-key -a master >/dev/null 2>&1; then
  echo "keyward is already installed or has data here; run this on a clean machine" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# A Claude Code config folder so agent linking has something to link; made before
# the snapshot, and removed after it, so it is not counted as residue.
made_claude=0
if [ ! -d "$HOME/.claude" ]; then mkdir "$HOME/.claude"; made_claude=1; fi

# Everything keyward may touch, by path and content.
snapshot() {
  {
    for root in "$support/keyward" "$support/keyward-vault" "$HOME/Library/Logs/keyward" "$HOME/.agents" "$HOME/.claude/CLAUDE.md"; do
      if [ -e "$root" ]; then
        find "$root"
        find "$root" -type f -exec shasum -a 256 {} +
      fi
    done
    ls "$HOME/Library/LaunchAgents" 2>/dev/null | grep -i keyward || true
    launchctl list | grep -i keyward || true
    if /usr/bin/security find-generic-password -s keyward-vault-key -a master >/dev/null 2>&1; then echo "keychain: vault key"; fi
    brew tap | grep -i keyward || true
    ls "$(brew --cache)/downloads" 2>/dev/null | grep -i keyward || true
  } | sort
}
snapshot > "$work/before"

rc="$work/rc"
printf 'export KW_LIFECYCLE_TOKEN="ghp_lifecycleFixture0123456789abcdef"\nexport KW_PLAIN=nothing-secret\n' > "$rc"
cp "$rc" "$work/rc.original"

echo "== install"
scripts/install-local-build.sh
keyward=$(brew --prefix)/bin/keyward

echo "== migrate"
printf 'yes\n' | "$keyward" migrate "$rc"
grep -q "cap://kw-lifecycle-token" "$rc"

echo "== link agents (needs a terminal, so through script)"
(sleep 2; printf 'yes\n'; sleep 2) | script -q /dev/null "$keyward" agents link
grep -q "keyward.md" "$HOME/.claude/CLAUDE.md"

echo "== run --only resolves the named variable, and only it"
# shellcheck disable=SC2016 # expanded by the child, after resolution
KW_LIFECYCLE_TOKEN=cap://kw-lifecycle-token KW_OTHER=cap://kw-lifecycle-token \
  "$keyward" run --only KW_LIFECYCLE_TOKEN -- sh -c \
  '[ "$KW_LIFECYCLE_TOKEN" = ghp_lifecycleFixture0123456789abcdef ] && [ "$KW_OTHER" = cap://kw-lifecycle-token ]'

echo "== uninstall --purge"
(cd "$work" && printf 'yes\n' | "$keyward" uninstall --purge)

echo "== check"
status=0
if ! cmp -s "$rc" "$work/rc.original"; then
  echo "FAIL: the migrated file did not come back byte for byte" >&2
  diff "$work/rc.original" "$rc" | sed 's/ghp_[A-Za-z0-9]*/ghp_…/g' >&2 || true
  status=1
fi
if [ "$made_claude" = 1 ]; then rmdir "$HOME/.claude" 2>/dev/null || true; fi
snapshot > "$work/after"
if ! diff "$work/before" "$work/after" >&2; then
  echo "FAIL: keyward left the differences above" >&2
  status=1
fi
[ "$status" = 0 ] && echo "PASS: nothing keyward created is left, and the file is back exactly"
exit "$status"
