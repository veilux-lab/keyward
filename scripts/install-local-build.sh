#!/bin/bash
# Installs this checkout through Homebrew the way a user gets a release, from a local
# veilux-lab/keyward tap, so install, migrate, and uninstall can be tried before
# shipping. Use a test Mac: it refuses to replace a keyward tap that is already there.
#
# Usage: scripts/install-local-build.sh [version]   (default: the next patch release)
set -euo pipefail
cd "$(dirname "$0")/.."

tap=veilux-lab/keyward
if brew tap | grep -qx "$tap"; then
  echo "$tap is already tapped. Remove keyward first: keyward uninstall" >&2
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

brew tap "$tap" "$source"
brew install --build-from-source "$tap/keyward"
echo "Installed keyward $version from this checkout. Remove it with: keyward uninstall"
