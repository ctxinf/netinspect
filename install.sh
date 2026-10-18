#!/bin/sh
# Install with: curl -fsSL https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh
set -eu

fail() { printf 'netinspect: %s\n' "$*" >&2; exit 1; }

for tool in curl tar sha256sum awk uname mktemp chmod mkdir mv; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required command not found: $tool"
done

[ "$(uname -s)" = Linux ] || fail 'Only Linux is supported.'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'Supported architectures: Linux amd64 and arm64.' ;;
esac

# Probe the active userspace libc, not the distribution name or kernel version.
libc_info=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
case "$libc_info" in
    'glibc '*) libc=glibc; libc_version=${libc_info#glibc } ;;
    *)
        libc_info=$(ldd --version 2>&1 || true)
        case "$libc_info" in
            *musl*)
                libc=musl
                libc_version=$(printf '%s\n' "$libc_info" | awk '/Version / {print $2; exit}')
                ;;
            *GLIBC*|*'GNU libc'*|*'GNU C Library'*)
                libc=glibc
                libc_version=$(printf '%s\n' "$libc_info" | awk 'NR==1 {print $NF}')
                ;;
            *) fail 'Cannot identify libc; supported: glibc >= 2.17 or musl >= 1.2.' ;;
        esac
        ;;
esac
case "$libc" in
    glibc)
        awk -v version="$libc_version" 'BEGIN {split(version,v,"."); exit !(v[1]>2 || (v[1]==2 && v[2]>=17))}' ||
            fail 'glibc 2.17 or newer is required.'
        ;;
    musl)
        awk -v version="$libc_version" 'BEGIN {split(version,v,"."); exit !(v[1]>1 || (v[1]==1 && v[2]>=2))}' ||
            fail 'musl 1.2 or newer is required.'
        ;;
esac
asset=netinspect_linux_${arch}_${libc}.tar.gz

version=${NETINSPECT_VERSION:-latest}
case "$version" in
    ''|*[!A-Za-z0-9.+-]*) fail 'Invalid NETINSPECT_VERSION.' ;;
esac
base=https://github.com/ctxinf/netinspect/releases
if [ "$version" = latest ]; then
    base=$base/latest/download
else
    base=$base/download/$version
fi

install_dir=${NETINSPECT_INSTALL_DIR:-"${HOME:?HOME is unset; set NETINSPECT_INSTALL_DIR}/.local/bin"}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' 0
trap 'exit 1' HUP INT TERM

printf 'Downloading netinspect (%s, %s, %s %s)...\n' "$version" "$arch" "$libc" "$libc_version"
token=${NETINSPECT_GITHUB_TOKEN:-${GH_TOKEN:-}}
if [ -n "$token" ]; then
    command -v python3 >/dev/null 2>&1 || fail 'Private downloads require python3.'
    api=https://api.github.com/repos/ctxinf/netinspect/releases
    if [ "$version" = latest ]; then
        api=$api/latest
    else
        api=$api/tags/$version
    fi
    curl -fLSs --retry 3 -H "Authorization: Bearer $token" \
        -H 'Accept: application/vnd.github+json' "$api" -o "$work_dir/release.json"
    python3 - "$work_dir" "$asset" <<'PY'
import json
from pathlib import Path
import sys

directory = Path(sys.argv[1])
assets = {a['name']: a['url'] for a in json.loads((directory / 'release.json').read_text())['assets']}
for name in (sys.argv[2], 'SHA256SUMS'):
    url = assets[name]
    if not url.startswith('https://api.github.com/repos/ctxinf/netinspect/releases/assets/'):
        raise SystemExit('Unexpected release asset URL')
    (directory / (name + '.url')).write_text(url)
PY
    for name in "$asset" SHA256SUMS; do
        curl -fLSs --retry 3 -H "Authorization: Bearer $token" \
            -H 'Accept: application/octet-stream' "$(cat "$work_dir/$name.url")" -o "$work_dir/$name"
    done
else
    curl -fLSs --retry 3 "$base/$asset" -o "$work_dir/$asset"
    curl -fLSs --retry 3 "$base/SHA256SUMS" -o "$work_dir/SHA256SUMS"
fi
checksum=$(awk -v asset="$asset" '$2 == asset {print $1}' "$work_dir/SHA256SUMS")
[ "${#checksum}" -eq 64 ] || fail 'Missing or invalid SHA256 checksum.'
case "$checksum" in *[!0-9a-fA-F]*) fail 'Invalid SHA256 checksum.' ;; esac
printf '%s  %s\n' "$checksum" "$asset" > "$work_dir/checksum"
(cd "$work_dir" && sha256sum -c checksum)
tar -xzf "$work_dir/$asset" -C "$work_dir" netinspect
chmod 755 "$work_dir/netinspect"
"$work_dir/netinspect" --version || fail "Cannot run the selected Linux $arch/$libc binary."
mkdir -p "$install_dir"
mv -f "$work_dir/netinspect" "$install_dir/netinspect"
printf 'Installed: %s/netinspect\n' "$install_dir"
case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf 'Add to your shell profile: export PATH="%s:$PATH"\n' "$install_dir" ;;
esac
