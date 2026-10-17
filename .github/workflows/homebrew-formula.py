#!/usr/bin/env python3
"""Generate the Linux amd64 Homebrew formula from a release archive."""

import hashlib
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

tag = os.environ["RELEASE_TAG"]
repository = os.environ["RELEASE_REPOSITORY"]
if not re.fullmatch(r"v?\d+(?:\.\d+)*", tag):
    raise SystemExit("Homebrew stable releases require a numeric version tag, e.g. v1.2.3")
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
    raise SystemExit("Invalid RELEASE_REPOSITORY")

archive = Path(sys.argv[1])
output = Path(sys.argv[2])
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
version = tag.removeprefix("v")
homepage = f"https://github.com/{repository}"
url = f"{homepage}/releases/download/{quote(tag, safe='')}/netinspect_linux_amd64.tar.gz"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(f'''class Netinspect < Formula
  desc "Monitor network connections of Linux processes"
  homepage "{homepage}"
  url "{url}"
  version "{version}"
  sha256 "{checksum}"
  license "MIT"

  depends_on :linux
  depends_on arch: :x86_64

  def install
    bin.install "netinspect"
  end

  test do
    assert_equal "netinspect {tag}", shell_output("#{{bin}}/netinspect --version").strip
  end
end
''')
