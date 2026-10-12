#!/bin/bash
set -euo pipefail

version=${1:?usage: merge-homebrew-bottles.sh version output-directory}
output=${2:?usage: merge-homebrew-bottles.sh version output-directory}
# Every bottle must match this release before Homebrew rewrites the formula.
output=$(python3 - "$version" "$output" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

version, directory = sys.argv[1], Path(sys.argv[2]).resolve()
root_url = f"https://github.com/veilux-lab/keyward/releases/download/v{version}"
tags = []
for path in sorted((directory / "bottles").glob("*.bottle.json")):
    (name, entry), = json.loads(path.read_text()).items()
    bottle = entry["bottle"]
    (tag, item), = bottle["tags"].items()
    if name != "veilux-lab/keyward/keyward" or entry["formula"]["pkg_version"] != version or \
            bottle["root_url"] != root_url or bottle["rebuild"] != 0 or \
            item["filename"] != f"keyward-{version}.{tag}.bottle.tar.gz":
        sys.exit(f"{path.name} belongs to another release")
    archive = directory / "bottles" / item["filename"]
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != item["sha256"]:
        sys.exit(f"{item['filename']} does not match its checksum")
    tags.append(tag)
if len(tags) != 1 or not tags[0].startswith("arm64_"):
    sys.exit("Expected exactly one Apple Silicon bottle")
print(directory)
PY
)

directory=$(mktemp -d "${TMPDIR:-/tmp}/keyward-merge.XXXXXX")
tap=veilux-lab/keyward
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 XDG_CONFIG_HOME="$directory/config"
mkdir -p "$XDG_CONFIG_HOME" "$directory/tap-source/Formula"
tapped=0
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ "$tapped" = 1 ]; then brew untap "$tap" || result=1; fi
  rm -rf "$directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $'\n'"$(brew tap)"$'\n' == *$'\n'"$tap"$'\n'* ]]; then
  echo "$tap is already tapped; leave it untouched" >&2
  exit 1
fi
cp "$output/Formula/keyward.rb" "$directory/tap-source/Formula/keyward.rb"
git -C "$directory/tap-source" init -q
git -C "$directory/tap-source" add Formula
git -C "$directory/tap-source" -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' commit -qm 'Disposable bottle merge tap'
tapped=1
brew tap "$tap" "$directory/tap-source"
tap_checkout=$(brew --repository "$tap")
brew trust --formula "$tap/keyward"
brew bottle --merge --write --no-commit "$output"/bottles/*.bottle.json
brew style "$tap_checkout/Formula/keyward.rb"
python3 - "$tap_checkout/Formula/keyward.rb" "$output/bottles" <<'PY'
import json
from pathlib import Path
import re
import sys

formula = Path(sys.argv[1]).read_text()
for path in Path(sys.argv[2]).glob("*.bottle.json"):
    (entry,) = json.loads(path.read_text()).values()
    for tag, item in entry["bottle"]["tags"].items():
        # Homebrew aligns the digests, so allow any spacing after the tag.
        if not re.search(rf'\b{tag}:\s+"{item["sha256"]}"', formula):
            sys.exit(f"Merged formula is missing the {tag} bottle")
PY
cp "$tap_checkout/Formula/keyward.rb" "$output/Formula/keyward.rb"
mv "$output"/bottles/*.bottle.tar.gz "$output/"
echo "Merged the Apple Silicon bottle into the release formula"
