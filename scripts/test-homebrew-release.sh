#!/bin/bash
set -euo pipefail

version=${1:?usage: test-homebrew-release.sh version output-directory}
output=${2:?usage: test-homebrew-release.sh version output-directory}
# Reject mismatched artifacts before even asking Homebrew for its paths.
output=$(python3 - "$version" "$output" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

version, directory = sys.argv[1], Path(sys.argv[2]).resolve()
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", version):
    sys.exit("Invalid release version")
formula = (directory / "Formula/keyward.rb").read_text()
archive = directory / f"keyward-{version}.tar.gz"
digests = re.findall(r'^\s*sha256 "([0-9a-f]{64})"$', formula, re.MULTILINE)
if len(digests) != 1 or hashlib.sha256(archive.read_bytes()).hexdigest() != digests[0]:
    sys.exit("Source archive checksum does not match the release formula")
if re.findall(r'^\s*version "([^"]+)"$', formula, re.MULTILINE) != [version]:
    sys.exit("Formula version does not match the release")
print(directory)
PY
)

umask 077
directory=$(mktemp -d "${TMPDIR:-/tmp}/keyward-brew.XXXXXX")
tap=veilux-lab/keyward-ci-review
package=keyward-ci-review
formula="$tap/$package"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1
export HOMEBREW_CACHE="$directory/cache" HOMEBREW_LOGS="$directory/logs"
export HOMEBREW_TEMP="$directory/temp" TMPDIR="$directory/temp" XDG_CONFIG_HOME="$directory/config"
mkdir -p "$HOMEBREW_CACHE" "$HOMEBREW_LOGS" "$HOMEBREW_TEMP" "$XDG_CONFIG_HOME"
installed=0 tapped=0 trusted=0 lock_owned=0
cellar= prefix= tap_checkout=
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ "$installed" = 1 ] && [ -d "$cellar/$package" ]; then
    brew uninstall "$formula" || result=1
  fi
  if [ "$tapped" = 1 ]; then
    if [ -n "$tap_checkout" ]; then rm -f "$tap_checkout/Formula/keyward.rb"; fi
    brew untap "$tap" || result=1
  fi
  if [ "$trusted" = 1 ]; then brew untrust --formula "$formula" || result=1; fi
  python3 - "$directory" "$prefix" "$package" "$lock_owned" <<'PY'
import os
from pathlib import Path
import shutil
import stat
import sys

directory, prefix, package = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
if prefix and sys.argv[4] == "1":
    lock = Path(prefix) / f"var/homebrew/locks/{package}.formula.lock"
    if os.path.lexists(lock):
        info = lock.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            sys.exit("Refusing to remove an unsafe fixture lock")
        lock.unlink()
if not directory.name.startswith("keyward-brew.") or directory.is_symlink():
    sys.exit("Refusing to remove an unsafe fixture directory")
for current, directories, files in os.walk(directory, followlinks=False):
    path = Path(current)
    info = path.lstat()
    if info.st_uid != os.getuid():
        sys.exit("Refusing to remove a fixture directory owned by someone else")
    path.chmod(info.st_mode | stat.S_IWUSR | stat.S_IXUSR)
    directories[:] = [name for name in directories if not (path / name).is_symlink()]
shutil.rmtree(directory)
PY
  if [ $? != 0 ]; then result=1; fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

prefix=$(brew --prefix)
cellar=$(brew --cellar)
taps=$(brew tap)
if [[ $'\n'"$taps"$'\n' == *$'\n'"$tap"$'\n'* ]] ||
   [ -e "$cellar/$package" ] || [ -L "$cellar/$package" ] ||
   [ -e "$prefix/var/homebrew/locks/$package.formula.lock" ]; then
  echo "Homebrew release fixture already exists; leave it untouched" >&2
  exit 1
fi
lock_owned=1

source="$directory/tap-source"
mkdir -p "$source/Formula"
cp "$output/keyward-$version.tar.gz" "$directory/source.tar.gz"
cp "$output/Formula/keyward.rb" "$source/Formula/keyward.rb"
python3 - "$source" "$directory/source.tar.gz" <<'PY'
from pathlib import Path
import re
import sys

source, archive = map(Path, sys.argv[1:])
formula = (source / "Formula/keyward.rb").read_text()
formula = formula.replace("class Keyward < Formula", "class KeywardCiReview < Formula", 1)
formula = re.sub(r'^  url "[^"]+"$', f'  url "{archive.as_uri()}"', formula, count=1, flags=re.MULTILINE)
formula = formula.replace('"keyward"', '"keyward-ci-review"').replace('/keyward ', '/keyward-ci-review ')
formula = formula.replace('std_go_args(ldflags: ldflags)', 'std_go_args(output: bin/"keyward-ci-review", ldflags: ldflags)')
formula = formula.replace("com.veilux-lab.keyward.homebrew", "com.veilux-lab.keyward.ci-review")
(source / "Formula/keyward-ci-review.rb").write_text(formula)
PY
git -C "$source" init -q
git -C "$source" add Formula
git -C "$source" -c user.name='Bueze Nwokolo' -c user.email='55523993+nwokolo24@users.noreply.github.com' commit -qm 'Disposable Homebrew release fixture'
tapped=1
brew tap "$tap" "$source"
tap_checkout=$(brew --repository "$tap")
chmod 644 "$tap_checkout/Formula/keyward.rb" "$tap_checkout/Formula/keyward-ci-review.rb"
trusted=1
brew trust --formula "$formula"
brew style "$tap_checkout/Formula/keyward.rb"
installed=1
brew install --build-from-source --skip-link "$formula"
brew test --force "$formula"
brew info --json=v2 "$formula" > "$directory/info.json"
python3 - "$directory/info.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as source:
    formula, = json.load(source)["formulae"]
service = formula["service"]
if formula["linked_keg"] is not None or service["name"]["macos"] != "com.veilux-lab.keyward.ci-review" or \
        service["run"][1:] != ["daemon"] or not service["run"][0].endswith("/bin/keyward-ci-review"):
    sys.exit("Unexpected fixture link or service metadata")
print("Exact source archive: install, formula test, style, and service metadata passed")
PY
