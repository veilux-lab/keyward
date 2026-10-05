#!/bin/bash
set -euo pipefail

version=${1:?usage: sign-release.sh version output-directory}
output=${2:?usage: sign-release.sh version output-directory}
for name in APPLE_CERTIFICATE_P12_BASE64 APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_NOTARY_KEY_P8 APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID; do
  if [ -z "${!name:-}" ]; then
    echo "Missing GitHub signing secret: $name" >&2
    exit 1
  fi
done
case "$APPLE_SIGNING_IDENTITY" in
  "Developer ID Application: "*) ;;
  *) echo "Release signing requires Developer ID Application" >&2; exit 1 ;;
esac

umask 077
signing_dir=$(mktemp -d "${RUNNER_TEMP:?}/keyward-signing.XXXXXX")
keychain="$signing_dir/signing.keychain-db"
cleanup() {
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$signing_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export KEYWARD_SIGNING_DIR="$signing_dir"
python3 - <<'PY'
import base64
import os
from pathlib import Path

directory = Path(os.environ["KEYWARD_SIGNING_DIR"])
encoded = "".join(os.environ["APPLE_CERTIFICATE_P12_BASE64"].split())
(directory / "certificate.p12").write_bytes(base64.b64decode(encoded, validate=True))
(directory / "notary.p8").write_text(os.environ["APPLE_NOTARY_KEY_P8"])
PY

# Rewrap locally so the private export password never becomes a process argument.
if ! openssl pkcs12 -in "$signing_dir/certificate.p12" -passin env:APPLE_CERTIFICATE_PASSWORD -nodes -out "$signing_dir/certificate.pem" 2>/dev/null; then
  openssl pkcs12 -legacy -in "$signing_dir/certificate.p12" -passin env:APPLE_CERTIFICATE_PASSWORD -nodes -out "$signing_dir/certificate.pem" 2>/dev/null
fi
openssl pkcs12 -export -in "$signing_dir/certificate.pem" -passout pass: -out "$signing_dir/import.p12" 2>/dev/null
# Only this disposable hosted runner's release key is in the temporary keychain.
security create-keychain -p "" "$keychain" >/dev/null
security set-keychain-settings -lut 21600 "$keychain" >/dev/null
security unlock-keychain -p "" "$keychain" >/dev/null
security import "$signing_dir/import.p12" -P "" -k "$keychain" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" "$keychain" >/dev/null

stage="$signing_dir/package"
mkdir -p "$stage"
lipo -create "$output/unsigned/arm64/keyward" "$output/unsigned/amd64/keyward" -output "$stage/keyward"
chmod 755 "$stage/keyward"
lipo -verify_arch arm64 x86_64 "$stage/keyward"
codesign --force --options runtime --timestamp --keychain "$keychain" --sign "$APPLE_SIGNING_IDENTITY" --identifier com.nwokolo24.keyward "$stage/keyward"
codesign --verify --strict --all-architectures -R '=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and identifier "com.nwokolo24.keyward"' "$stage/keyward"
cp LICENSE "$stage/LICENSE"
cat > "$stage/INSTALL.txt" <<'TEXT'
Keyward for macOS 15 or later (Apple Silicon and Intel)

In Terminal, run the keyward binary from this disk image:
  /Volumes/Keyward/keyward service install
This installs the signed CLI in ~/.local/bin and starts its login daemon.
Add ~/.local/bin to PATH if needed, then eject the disk image.

Use keyward service status to check the daemon. To upgrade, run service install
from the new disk image. A change of signing identity may require Keychain approval.
Source-built Homebrew installations use a separate service: stop that installation
with keyward service uninstall before installing this signed CLI.

Before uninstalling, use keyward restore for any files where you want plaintext
values returned, then keyward service uninstall. Keychain items are retained.
https://github.com/veilux-lab/keyward/blob/main/doc/install.md
TEXT
dmg="$signing_dir/keyward-$version-darwin-universal.dmg"
hdiutil create -volname Keyward -srcfolder "$stage" -format UDZO "$dmg" >/dev/null
codesign --force --timestamp --keychain "$keychain" --sign "$APPLE_SIGNING_IDENTITY" "$dmg"
xcrun notarytool submit "$dmg" --key "$signing_dir/notary.p8" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID" --wait --timeout 20m --output-format json > "$signing_dir/notary.json"
python3 - "$signing_dir/notary.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as receipt:
    if json.load(receipt).get("status") != "Accepted":
        sys.exit("Apple did not accept the notarization submission")
PY
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
spctl --assess --type open --context context:primary-signature "$dmg"
cp "$dmg" "$output/keyward-$version-darwin-universal.dmg"
