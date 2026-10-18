#!/usr/bin/env python3
"""Generate an architecture-aware Linux glibc Homebrew formula."""
import hashlib
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

tag = os.environ['RELEASE_TAG']
repository = os.environ['RELEASE_REPOSITORY']
if not re.fullmatch(r'v?\d+(?:\.\d+)*', tag):
    raise SystemExit('Homebrew stable releases require a numeric version tag')
if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
    raise SystemExit('Invalid RELEASE_REPOSITORY')
directory, output = map(Path, sys.argv[1:])
homepage = f'https://github.com/{repository}'
blocks = []
for arch, condition in [('amd64', 'on_intel'), ('arm64', 'on_arm')]:
    name = f'netinspect_linux_{arch}_glibc.tar.gz'
    checksum = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    requirement = 'x86_64' if arch == 'amd64' else 'arm64'
    blocks.append(f'''  {condition} do
    depends_on arch: :{requirement}
    url "{homepage}/releases/download/{quote(tag, safe='')}/{name}"
    sha256 "{checksum}"
  end''')
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(f'''class Netinspect < Formula
  desc "Monitor network connections of Linux processes"
  homepage "{homepage}"
  version "{tag.removeprefix('v')}"
  license "MIT"

  depends_on :linux

{chr(10).join(blocks)}

  def install
    bin.install "netinspect"
  end

  test do
    assert_equal "netinspect {tag}", shell_output("#{{bin}}/netinspect --version").strip
  end
end
''')
