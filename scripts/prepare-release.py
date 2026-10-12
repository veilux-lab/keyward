import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def prepare(version, output, release_type, revision, run_id):
    archive = f"keyward-{version}.tar.gz"
    assets = [archive, "SHA256SUMS", "release.json"]
    files = [archive]
    if release_type == "signed":
        dmg = f"keyward-{version}-darwin-universal.dmg"
        assets.append(dmg)
        files.append(dmg)
    bottles = sorted(path.name for path in output.glob(f"keyward-{version}.*.bottle.tar.gz"))
    if len(bottles) != 1 or ".arm64_" not in bottles[0]:
        sys.exit("Expected exactly one Apple Silicon Homebrew bottle")
    assets += bottles
    files += bottles
    digests = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in files}
    provenance = {"version": version, "source_commit": revision, "run_id": run_id,
                  "release_type": release_type, "assets": assets}
    if release_type == "signed":
        provenance.update(macos_minimum="15.0", signing_identifier="com.nwokolo24.keyward")
    (output / "release.json").write_text(json.dumps(provenance, indent=2) + "\n")
    digests["release.json"] = hashlib.sha256((output / "release.json").read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in digests.items()))
    notes = f"Built from `{revision}`.\n\n"
    if release_type == "signed":
        notes += ("The disk image contains a Developer ID-signed, notarized universal CLI "
                  "for macOS 15 or later. Follow INSTALL.txt inside the image.\n\n")
    notes += ("Homebrew installs a prebuilt bottle on Apple Silicon Macs that use its "
              "default location, and builds from the matching source archive otherwise. "
              "No paid Apple membership is needed.\n\n"
              "```sh\nbrew tap veilux-lab/keyward https://github.com/veilux-lab/keyward.git\n"
              "brew install veilux-lab/keyward/keyward\n```\n\n"
              "Daemon upgrades may require Keychain approval.\n")
    (output / "notes.md").write_text(notes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Record the source and assets for a release")
    parser.add_argument("version")
    parser.add_argument("output", type=Path)
    parser.add_argument("--release-type", choices=("source", "signed"), default="source")
    args = parser.parse_args()
    prepare(args.version, args.output, args.release_type, os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"])
