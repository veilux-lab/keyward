#!/bin/bash
set -euo pipefail

version=${1:?usage: publish-release.sh version output-directory}
output=${2:?usage: publish-release.sh version output-directory}
tag="v$version"
assets=("keyward-$version.tar.gz" "keyward-$version-darwin-universal.dmg" SHA256SUMS release.json)
for asset in "${assets[@]}"; do
  test -f "$output/$asset" || { echo "Missing release asset: $asset" >&2; exit 1; }
done
remote=$(git ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}")
if [ -n "$remote" ]; then
  revision=$(printf '%s\n' "$remote" | tail -1 | cut -f1)
  test "$revision" = "${GITHUB_SHA:?}" || { echo "Release tag belongs to another source commit" >&2; exit 1; }
fi

directory=$(mktemp -d "${TMPDIR:-/tmp}/keyward-publish.XXXXXX")
trap 'rm -rf "$directory"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if gh release view "$tag" --json isDraft,targetCommitish,assets > "$directory/state.json"; then
  state=$(python3 - "$directory/state.json" <<'PY'
import json
import os
import sys

with open(sys.argv[1]) as source:
    release = json.load(source)
if release["isDraft"]:
    if release["targetCommitish"] != os.environ["GITHUB_SHA"]:
        sys.exit("Existing release draft belongs to another source commit")
    print("draft")
else:
    print("published")
PY
  )
  if [ "$state" = published ]; then
    python3 - "$directory/state.json" "${assets[@]}" <<'PY'
import json
import sys

with open(sys.argv[1]) as source:
    names = {asset["name"] for asset in json.load(source)["assets"]}
if not set(sys.argv[2:]).issubset(names):
    sys.exit("Existing public release is incomplete; refusing to overwrite it")
PY
    gh release download "$tag" --pattern "keyward-$version.tar.gz" --dir "$directory"
    cmp "$directory/keyward-$version.tar.gz" "$output/keyward-$version.tar.gz"
    echo "Published release retained; source archive matches"
    exit 0
  fi
else
  gh release create "$tag" --draft --target "${GITHUB_SHA:?}" --title "Keyward $tag" --notes-file "$output/notes.md"
fi
paths=()
for asset in "${assets[@]}"; do paths+=("$output/$asset"); done
# Drafts can resume an interrupted upload; public assets are never replaced.
gh release upload "$tag" "${paths[@]}" --clobber
gh release edit "$tag" --draft=false --latest=false
