#!/bin/bash
set -euo pipefail

version=${1:?usage: build-homebrew-bottle.sh version output-directory}
output=${2:?usage: build-homebrew-bottle.sh version output-directory}
# The bottle must carry the real formula name, so this installs `keyward` itself.
if [ "${GITHUB_ACTIONS:-}" != true ]; then
  echo "Homebrew bottles are built only on disposable CI runners" >&2
  exit 1
fi
output=$(python3 "$(dirname "$0")/check-release-formula.py" "$version" "$output")

directory=$(mktemp -d "${TMPDIR:-/tmp}/keyward-bottle.XXXXXX")
tap=veilux-lab/keyward
formula="$tap/keyward"
root_url="https://github.com/veilux-lab/keyward/releases/download/v$version"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1
export HOMEBREW_CACHE="$directory/cache" HOMEBREW_LOGS="$directory/logs" XDG_CONFIG_HOME="$directory/config"
mkdir -p "$HOMEBREW_CACHE" "$HOMEBREW_LOGS" "$XDG_CONFIG_HOME" "$directory/tap-source/Formula" "$directory/bottles" "$directory/served"
installed=0 tapped=0
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ "$installed" = 1 ]; then brew uninstall --ignore-dependencies "$formula" >/dev/null 2>&1; fi
  if [ "$tapped" = 1 ]; then brew untap "$tap" || result=1; fi
  # Go's module cache is read-only.
  chmod -R u+w "$directory" && rm -rf "$directory" || result=1
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $'\n'"$(brew tap)"$'\n' == *$'\n'"$tap"$'\n'* ]] || [ -e "$(brew --cellar)/keyward" ]; then
  echo "Keyward is already tapped or installed on this runner" >&2
  exit 1
fi

python3 - "$output" "$version" "$directory/tap-source/Formula/keyward.rb" <<'PY'
from pathlib import Path
import re
import sys

output, version, target = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
archive = (output / f"keyward-{version}.tar.gz").as_uri()
formula = (output / "Formula/keyward.rb").read_text()
target.write_text(re.sub(r'^  url "[^"]+"$', f'  url "{archive}"', formula, count=1, flags=re.MULTILINE))
PY
git -C "$directory/tap-source" init -q
git -C "$directory/tap-source" add Formula
git -C "$directory/tap-source" -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' commit -qm 'Disposable bottle tap'
tapped=1
brew tap "$tap" "$directory/tap-source"
tap_checkout=$(brew --repository "$tap")
brew trust --formula "$formula"
installed=1
brew install --build-bottle "$formula"
brew test "$formula"
(cd "$directory/bottles" && brew bottle --no-rebuild --json --root-url "$root_url" "$formula")
read -r local_name release_name < <(python3 - "$directory/bottles" <<'PY'
import json
from pathlib import Path
import sys

(path,) = Path(sys.argv[1]).glob("*.bottle.json")
(entry,) = json.loads(path.read_text()).values()
(item,) = entry["bottle"]["tags"].values()
print(item["local_filename"], item["filename"])
PY
)

# Pour through the formula, as users will, with the bottle served locally.
brew uninstall "$formula"
installed=0
# Homebrew 7 drops a formula's trust when it is uninstalled.
brew trust --formula "$formula"
brew bottle --merge --write --no-commit "$directory"/bottles/*.bottle.json
cp "$directory/bottles/$local_name" "$directory/served/$release_name"
python3 - "$tap_checkout/Formula/keyward.rb" "$directory/served" <<'PY'
from pathlib import Path
import re
import sys

formula, served = Path(sys.argv[1]), Path(sys.argv[2])
text, count = re.subn(r'^    root_url "[^"]+"$', f'    root_url "{served.as_uri()}"', formula.read_text(), flags=re.MULTILINE)
if count != 1:
    sys.exit("Merged formula has no bottle root URL")
formula.write_text(text)
PY
installed=1
brew install "$formula"
brew test "$formula"
brew info --json=v2 "$formula" | python3 -c '
import json, sys
(formula,) = json.load(sys.stdin)["formulae"]
if not formula["installed"][0]["poured_from_bottle"]:
    sys.exit("Homebrew built from source instead of pouring the bottle")
'

mkdir -p "$output/bottles"
cp "$directory/bottles/$local_name" "$output/bottles/$release_name"
cp "$directory"/bottles/*.bottle.json "$output/bottles/"
echo "Bottle $release_name: build, formula test, merge, and pour passed"
