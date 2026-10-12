import hashlib
from pathlib import Path
import re
import sys

# Rejects mismatched artifacts before Homebrew is asked to touch them.
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
