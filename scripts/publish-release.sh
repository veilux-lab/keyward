#!/bin/bash
set -euo pipefail

version=${1:?usage: publish-release.sh version output-directory [source|signed]}
output=${2:?usage: publish-release.sh version output-directory [source|signed]}
release_type=${3:-source}
tag="v$version"
assets=("keyward-$version.tar.gz" SHA256SUMS release.json)
case "$release_type" in
  source) ;;
  signed) assets+=("keyward-$version-darwin-universal.dmg") ;;
  *) echo "Release type must be source or signed" >&2; exit 1 ;;
esac
# Bytewise glob order matches the list recorded in release.json.
LC_ALL=C
bottles=0
for bottle in "$output/keyward-$version".*.bottle.tar.gz; do
  if [ -f "$bottle" ]; then assets+=("${bottle##*/}"); bottles=$((bottles + 1)); fi
done
if [ "$bottles" = 0 ]; then
  echo "Missing Homebrew bottles" >&2
  exit 1
fi
for asset in "${assets[@]}"; do
  test -f "$output/$asset" || { echo "Missing release asset: $asset" >&2; exit 1; }
done
validate_manifest() {
  python3 - "$1" "$version" "$release_type" "${assets[@]}" <<'PY'
import json
import os
import sys

with open(sys.argv[1]) as source:
    release = json.load(source)
if release.get("version") != sys.argv[2] or release.get("source_commit") != os.environ["GITHUB_SHA"] or \
        release.get("release_type") != sys.argv[3] or release.get("assets") != sys.argv[4:]:
    sys.exit("Release provenance or asset list does not match this run")
PY
}
validate_manifest "$output/release.json"
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
  python3 - "$directory/state.json" "${assets[@]}" <<'PY'
import json
import sys

with open(sys.argv[1]) as source:
    release = json.load(source)
names = {asset["name"] for asset in release["assets"]}
expected = set(sys.argv[2:])
if release["isDraft"]:
    if not names.issubset(expected):
        sys.exit("Existing draft contains assets for another release type")
elif names != expected:
    sys.exit("Existing public release is incomplete or has unexpected assets; refusing to overwrite it")
PY
  if python3 - "$directory/state.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as source:
    sys.exit(0 if any(asset["name"] == "release.json" for asset in json.load(source)["assets"]) else 1)
PY
  then
    gh release download "$tag" --pattern release.json --dir "$directory"
    validate_manifest "$directory/release.json"
  fi
  if [ "$state" = published ]; then
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
gh release edit "$tag" --notes-file "$output/notes.md" --draft=false --latest=false
