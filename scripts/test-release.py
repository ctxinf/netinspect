#!/usr/bin/env python3
"""Offline release selection and formula checks; no downloads are performed."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import sys

root = Path(__file__).resolve().parents[1]
source = (root / 'install.sh').read_text().split('\nversion=', 1)[0]
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    mocks = directory / 'bin'
    mocks.mkdir()
    for command, body in {
        'uname': 'case "$1" in -s) echo Linux;; -m) echo "$TEST_ARCH";; esac',
        'getconf': '[ "$TEST_LIBC" = glibc ] || exit 1; echo "glibc $TEST_VERSION"',
        'ldd': '[ "$TEST_LIBC" = musl ] || exit 1; printf "musl libc\\nVersion %s\\n" "$TEST_VERSION"; exit 1',
    }.items():
        path = mocks / command
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)
    for arch, libc, version, expected in [
        ('x86_64', 'glibc', '2.17', 'amd64_glibc'),
        ('aarch64', 'glibc', '2.39', 'arm64_glibc'),
        ('x86_64', 'musl', '1.2.5', 'amd64_musl'),
        ('aarch64', 'musl', '1.2.0', 'arm64_musl'),
        ('x86_64', 'glibc', '2.16', None),
        ('x86_64', 'musl', '1.1.24', None),
        ('x86_64', 'unknown', '', None),
        ('i686', 'glibc', '2.39', None),
    ]:
        result = subprocess.run(['sh'], input=source + '\nprintf "%s" "$asset"\n',
            text=True, capture_output=True, env={**os.environ, 'PATH': f'{mocks}:{os.environ["PATH"]}',
            'TEST_ARCH': arch, 'TEST_LIBC': libc, 'TEST_VERSION': version})
        if expected:
            assert result.returncode == 0 and result.stdout == f'netinspect_linux_{expected}.tar.gz', result
        else:
            assert result.returncode != 0, result
    for arch in ('amd64', 'arm64'):
        (directory / f'netinspect_linux_{arch}_glibc.tar.gz').write_bytes(arch.encode())
    formula = directory / 'netinspect.rb'
    subprocess.run(['python3', str(root / '.github/workflows/homebrew-formula.py'), str(directory), str(formula)],
        env={**os.environ, 'RELEASE_TAG': 'v1.2.3', 'RELEASE_REPOSITORY': 'ctxinf/netinspect'}, check=True)
    text = formula.read_text()
    for arch, block in [('amd64', 'on_intel'), ('arm64', 'on_arm')]:
        assert block in text and f'netinspect_linux_{arch}_glibc.tar.gz' in text
        assert hashlib.sha256(arch.encode()).hexdigest() in text
    assert 'depends_on arch: :x86_64' in text and 'depends_on arch: :arm64' in text
    assert 'depends_on arch: [' not in text
    print('Release checks passed: architecture/libc selection, unsupported systems, formula URLs and checksums')

# With real release archives, exercise the entire public installer offline,
# including checksum rejection before installation.
if len(sys.argv) > 1:
    assets = Path(sys.argv[1]).resolve()
    for arch in ('amd64', 'arm64'):
        for libc in ('glibc', 'musl'):
            assert (assets / f'netinspect_linux_{arch}_{libc}.tar.gz').is_file()
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        mocks = directory / 'bin'
        mocks.mkdir()
        curl = mocks / 'curl'
        curl.write_text('#!/usr/bin/env python3\n' + '''
import os
from pathlib import Path
import shutil
import sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
name = url.rsplit('/', 1)[1]
output = Path(args[args.index('-o') + 1])
if os.environ.get('BAD_CHECKSUM') and name == 'SHA256SUMS':
    output.write_text('0' * 64 + '  netinspect_linux_amd64_glibc.tar.gz\\n')
else:
    shutil.copyfile(Path(os.environ['TEST_ASSETS']) / name, output)
''')
        curl.chmod(0o755)
        destination = directory / 'installed'
        env = {**os.environ, 'PATH': f'{mocks}:{os.environ["PATH"]}',
               'TEST_ASSETS': str(assets), 'NETINSPECT_INSTALL_DIR': str(destination),
               'NETINSPECT_VERSION': 'v0.0.0', 'NETINSPECT_GITHUB_TOKEN': '', 'GH_TOKEN': ''}
        result = subprocess.run(['sh', str(root / 'install.sh')], env=env, text=True, capture_output=True)
        assert result.returncode == 0 and (destination / 'netinspect').is_file(), result
        before = (destination / 'netinspect').read_bytes()
        result = subprocess.run(['sh', str(root / 'install.sh')],
            env={**env, 'BAD_CHECKSUM': '1'}, text=True, capture_output=True)
        assert result.returncode != 0, result
        assert (destination / 'netinspect').read_bytes() == before
        print('Actual package install and checksum rejection passed (offline)')
