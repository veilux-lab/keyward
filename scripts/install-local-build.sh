#!/bin/bash
# Installs this checkout through Homebrew the way a user gets a release, from a local
# veilux-lab/keyward tap, so install, migrate, and uninstall can be tried before
# shipping. Use a test Mac: it refuses to replace a keyward tap that is already there.
# With --upgrade it instead points the existing tap at this build and runs
# brew upgrade, the way a user moves from a published release.
#
# Usage: scripts/install-local-build.sh [--upgrade] [version]   (default: the next patch)
set -euo pipefail
cd "$(dirname "$0")/.."

tap=veilux-lab/keyward
upgrade=0
if [ "${1:-}" = --upgrade ]; then upgrade=1; shift; fi
if brew tap | grep -qx "$tap"; then
  if [ "$upgrade" = 0 ]; then
    echo "$tap is already tapped. Remove keyward first (keyward uninstall), or use --upgrade" >&2
    exit 1
  fi
elif [ "$upgrade" = 1 ]; then
  echo "--upgrade needs keyward installed from $tap first" >&2
  exit 1
fi
latest=$(git tag --list 'v*' --sort=-v:refname | head -1)
latest=${latest#v}
version=${1:-${latest%.*}.$(( ${latest##*.} + 1 ))}

# Kept under bin/, which git ignores, so a reinstall can reuse the archive.
out="$PWD/bin/local-release"
rm -rf "$out"
go run ./cmd/keyward-release -version "$version" -out "$out/release"

source="$out/tap"
mkdir -p "$source/Formula"
sed -E "s|^  url \".*\"$|  url \"file://$out/release/keyward-$version.tar.gz\"|" \
  "$out/release/Formula/keyward.rb" > "$source/Formula/keyward.rb"
git -C "$source" init -q
git -C "$source" add Formula
git -C "$source" -c user.name=local -c user.email=local@example.invalid commit -qm "Local build $version"

if [ "$upgrade" = 1 ]; then
  # Homebrew updates taps from their remote; a local commit is enough for one upgrade.
  checkout=$(brew --repository "$tap")
  cp "$source/Formula/keyward.rb" "$checkout/Formula/keyward.rb"
  git -C "$checkout" -c user.name=local -c user.email=local@example.invalid commit -qam "Local build $version"
  HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade --build-from-source "$tap/keyward"
  echo "Upgraded keyward to $version from this checkout. Run any keyward command to restart the daemon."
  exit 0
fi
brew tap "$tap" "$source"
brew install --build-from-source "$tap/keyward"
echo "Installed keyward $version from this checkout. Remove it with: keyward uninstall"
