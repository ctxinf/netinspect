#!/usr/bin/env python3
"""Reject preload libraries that exceed the declared libc ABI baseline."""
import os
import re
import subprocess
import sys

library = sys.argv[1]
versions = subprocess.check_output(['readelf', '--version-info', library], text=True)
needed = subprocess.check_output(['readelf', '-d', library], text=True)
if os.environ.get('LIBC', 'glibc') == 'musl':
    assert 'GLIBC_' not in versions, versions
    assert 'libc.musl-' in needed, needed
else:
    requirements = [tuple(map(int, v.split('.'))) for v in re.findall(r'GLIBC_([0-9.]+)', versions)]
    assert requirements and max(requirements) <= (2, 17), versions
    assert 'libc.so.6' in needed, needed
print('Preload ABI baseline verified')
