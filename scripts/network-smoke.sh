#!/usr/bin/env bash
# Public network traffic samples for netinspect. No credentials are required.
# Usage: bash scripts/network-smoke.sh
# Override proxies with NETINSPECT_HTTP_PROXY / NETINSPECT_SOCKS5_PROXY,
# or the conventional http_proxy/HTTP_PROXY and all_proxy/ALL_PROXY variables.
# Proxy values are never printed; avoid putting credentials in committed files.
# Requires Bash and timeout; individual steps skip missing client tools.

set -u

STEP_TIMEOUT=${NETINSPECT_STEP_TIMEOUT:-25}
GO_TIMEOUT=${NETINSPECT_GO_TIMEOUT:-90}
HTTP_PROXY_URL=${NETINSPECT_HTTP_PROXY:-${http_proxy:-${HTTP_PROXY:-http://127.0.0.1:7890}}}
SOCKS_PROXY_URL=${NETINSPECT_SOCKS5_PROXY:-${all_proxy:-${ALL_PROXY:-socks5h://127.0.0.1:7891}}}

if ! command -v timeout >/dev/null 2>&1; then
    echo 'Required command missing: timeout (GNU coreutils)' >&2
    exit 1
fi
for value in "$STEP_TIMEOUT" "$GO_TIMEOUT"; do
    if [[ ! $value =~ ^[1-9][0-9]*$ ]]; then
        echo 'Timeouts must be positive integer seconds.' >&2
        exit 1
    fi
done

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/netinspect-smoke.XXXXXXXX") || exit 1
trap 'rm -rf -- "$tmp_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Select proxy behavior explicitly per step. This only clears conventional
# proxy variables; an enclosing preload/ptrace/netns monitor still applies.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY

passed=0
failed=0
skipped=0
step=0
run_step() {
    local label=$1 limit=$2 tool=$3 rc
    shift 3
    step=$((step + 1))
    printf '\n[%d/9] %s\n' "$step" "$label"
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'SKIP: missing %s\n' "$tool"
        skipped=$((skipped + 1))
        return
    fi
    # Keep client diagnostics local: proxy errors may contain private addresses
    # or credentials. The summary reports only exit status.
    timeout --kill-after=2s "${limit}s" "$@" >"$tmp_dir/output" 2>&1
    rc=$?
    if (( rc == 0 )); then
        echo 'PASS'
        passed=$((passed + 1))
    else
        printf 'FAIL: exit=%d (124 means timeout)\n' "$rc"
        failed=$((failed + 1))
    fi
}

run_step 'HTTPS example.com (no explicit proxy)' "$STEP_TIMEOUT" curl \
    curl --silent --show-error --fail --location --proxy '' \
    --connect-timeout 8 --max-time "$STEP_TIMEOUT" --output /dev/null https://example.com

run_step 'HTTPS example.com via HTTP proxy (CONNECT)' "$STEP_TIMEOUT" curl \
    curl --silent --show-error --fail --location --noproxy '' --proxy "$HTTP_PROXY_URL" \
    --connect-timeout 8 --max-time "$STEP_TIMEOUT" --output /dev/null https://example.com

# --socks5-hostname forces SOCKS5 with proxy-side DNS, even for a bare host:port.
SOCKS_PROXY_ADDR=${SOCKS_PROXY_URL#*://}
run_step 'HTTPS example.com via SOCKS5 proxy (remote DNS)' "$STEP_TIMEOUT" curl \
    curl --silent --show-error --fail --location --noproxy '' --socks5-hostname "$SOCKS_PROXY_ADDR" \
    --connect-timeout 8 --max-time "$STEP_TIMEOUT" --output /dev/null https://example.com

run_step 'DNS: example.com A via system resolver (normally UDP/53)' "$STEP_TIMEOUT" dig \
    dig +time=5 +tries=1 +short example.com A

# Fixed public resolver address avoids a bootstrap DNS lookup for dns.google.
run_step 'DoH: example.com A via Google HTTPS JSON API' "$STEP_TIMEOUT" curl \
    curl --silent --show-error --fail --proxy '' --resolve dns.google:443:8.8.8.8 \
    --connect-timeout 8 --max-time "$STEP_TIMEOUT" --output /dev/null \
    'https://dns.google/resolve?name=example.com&type=A'

# A length-prefixed DNS wire query over TLS (RFC 7858), not just a TLS handshake.
cat >"$tmp_dir/dot.py" <<'DOT'
import socket
import ssl
import struct

query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
def read_exact(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError("truncated DNS response")
        data += chunk
    return data

with socket.create_connection(("1.1.1.1", 853), timeout=8) as raw:
    with ssl.create_default_context().wrap_socket(raw, server_hostname="cloudflare-dns.com") as tls:
        tls.sendall(struct.pack("!H", len(query)) + query)
        size = struct.unpack("!H", read_exact(tls, 2))[0]
        response = read_exact(tls, size)
        if len(response) < 12 or response[:2] != query[:2] or not response[2] & 0x80 or response[3] & 0x0f:
            raise RuntimeError("invalid or unsuccessful DNS response")
        print("Received DNS response over TLS")
DOT
run_step 'DoT: example.com A via Cloudflare TLS/853' "$STEP_TIMEOUT" python3 \
    python3 "$tmp_dir/dot.py"

cat >"$tmp_dir/main.go" <<'GO'
package main

import (
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
)

func main() {
    client := &http.Client{Timeout: 20 * time.Second}
    resp, err := client.Get("https://golang.org")
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    defer resp.Body.Close()
    if _, err := io.Copy(io.Discard, resp.Body); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    fmt.Println(resp.Status)
    if resp.StatusCode >= 400 { os.Exit(1) }
}
GO
# Ignore the enclosing repo's go.mod and use the installed toolchain offline.
# No module dependencies; compilation gets a separate, longer timeout.
run_step 'go run: HTTPS golang.org (follows redirects)' "$GO_TIMEOUT" go \
    env GO111MODULE=off GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
    go run "$tmp_dir/main.go"

# This intentionally attempts SSH without credentials. Authentication denial
# is expected; no personal keys, agent, SSH config, or known_hosts are used.
run_step 'SSH: git@github.com:22 (authentication failure is expected)' "$STEP_TIMEOUT" ssh \
    ssh -F /dev/null -T -p 22 -o BatchMode=yes -o ConnectTimeout=8 \
    -o ConnectionAttempts=1 -o IdentityAgent=none -o IdentitiesOnly=yes \
    -o IdentityFile=none -o PubkeyAuthentication=no -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o GlobalKnownHostsFile=/dev/null git@github.com

# Keep stdin open briefly so telnet can establish a plain TCP connection.
# There is deliberately no TLS handshake on this port; timeout may be expected.
run_step 'Telnet: plain TCP to 1.1.1.1:443 (no TLS)' "$STEP_TIMEOUT" telnet \
    bash -c 'sleep 3 | telnet 1.1.1.1 443'

printf '\nFinished: %d passed, %d failed, %d skipped.\n' "$passed" "$failed" "$skipped"
echo 'SSH authentication denial and a telnet timeout do not imply TCP connection failure.'
echo 'Inspect the dashboard during execution; records disappear when the monitored command exits.'
# Each step is a traffic sample; failure never prevents subsequent samples.
exit 0
