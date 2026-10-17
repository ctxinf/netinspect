<h1 align="center">◉ netinspect</h1>
<p align="center"><a href="README.md">中文</a> · English</p>

<p align="center">Process-level network monitoring for Linux command-line programs. Inspect the connections from a single run in your browser.</p>

- Prefix a command with `netinspect` to start monitoring and its Web dashboard.
- Inspect destinations, processes, connection latency, upload/download bytes, results, and visible TLS SNI / ALPN. The `netns` mode also records DNS questions and answers.
- The live dashboard provides status filters, search, sorting, pagination, configurable columns, record details, and light/dark themes.
- Choose from four modes: `preload`, `ptrace`, `netns`, and `observe`.
- Written in Go, with the dashboard and preload library embedded in the binary. No separate Web deployment is needed.
- Records stay in memory, with a default **128 MiB** storage budget. The dashboard stays open for **30 minutes** after the command exits, then releases its data.
- Connection metadata only: no MITM, TLS decryption, or storage of request/response bodies.

## Contents

- [1. Installation](#1-installation)
  - [1.1 Install script](#11-install-script)
  - [1.2 Manual download](#12-manual-download)
  - [1.3 Homebrew](#13-homebrew)
  - [1.4 Build from source](#14-build-from-source)
- [2. Usage](#2-usage)
  - [2.1 Start monitoring](#21-start-monitoring)
  - [2.2 Open the dashboard](#22-open-the-dashboard)
  - [2.3 Exit and retention](#23-exit-and-retention)
  - [2.4 Configuration](#24-configuration)
- [3. Mode comparison](#3-mode-comparison)
- [4. Development and releases](#4-development-and-releases)
- [License](#license)

## 1. Installation

Prebuilt packages currently support **Linux x86_64 / amd64**. The default `preload` mode uses a glibc shared library. Release packages are built on Ubuntu 22.04 and require glibc 2.35 or newer; for other environments, try building from source.

This repository is currently private. Downloading its scripts, source, and Releases requires an authorized GitHub account or token. The `GH_TOKEN` below needs **Contents: Read** access to `ctxinf/netinspect`.

<details id="11-install-script" open>
<summary>1.1 Install script</summary>

Go is not required. Install `curl`, `tar`, `sha256sum`, and `python3`, export an authorized token as `GH_TOKEN`, then run:

```sh
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
  https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
netinspect --version
```

The script downloads the latest stable Release, verifies its SHA256 checksum, and installs to `~/.local/bin`. Add the `PATH` setting to your shell configuration for future terminals.

To choose a version and installation directory, download the script first:

```sh
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
  https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh -o /tmp/netinspect-install.sh
NETINSPECT_VERSION=v0.1.1 NETINSPECT_INSTALL_DIR="$HOME/.local/bin" \
  sh /tmp/netinspect-install.sh
```

`NETINSPECT_VERSION` defaults to `latest`; use the full tag when specifying a version. `NETINSPECT_INSTALL_DIR` must be writable by the current user. Run the script again to update.

</details>

<details id="12-manual-download">
<summary>1.2 Manual download</summary>

Sign in to GitHub, download `netinspect_linux_amd64.tar.gz` and `SHA256SUMS` from [Releases](https://github.com/ctxinf/netinspect/releases/latest), and place both files in the same directory:

```sh
sha256sum -c SHA256SUMS
tar -xzf netinspect_linux_amd64.tar.gz
mkdir -p "$HOME/.local/bin"
install -m 755 netinspect "$HOME/.local/bin/netinspect"
export PATH="$HOME/.local/bin:$PATH"
netinspect --version
```

The archive includes `netinspect`, the README, and the license. The preload library and dashboard are embedded in the executable.

</details>

<details id="13-homebrew">
<summary>1.3 Homebrew</summary>

Stable releases automatically update `Formula/netinspect.rb` in [ctxinf/homebrew-tap](https://github.com/ctxinf/homebrew-tap). It currently provides a binary formula for Linux x86_64.

The formula points to a private Release, and authentication for private Homebrew asset downloads has not been configured. Adding the tap alone does not enable anonymous installation. Use the token-based install script or manual download above for now.

</details>

<details id="14-build-from-source">
<summary>1.4 Build from source</summary>

Requires Linux, Go **1.27.2 or newer**, a C compiler, and `make`. Configure access to the private repository through GitHub CLI or a Git credential helper first:

```sh
git clone https://github.com/ctxinf/netinspect.git
cd netinspect
make -C modes/preload
sh scripts/build.sh -o netinspect
mkdir -p "$HOME/.local/bin"
install -m 755 netinspect "$HOME/.local/bin/netinspect"
export PATH="$HOME/.local/bin:$PATH"
netinspect --version
```

Build `modes/preload/libnetinspect.so` before compiling Go so it can be embedded. `scripts/build.sh` injects the nearest tag and current commit for the CLI and dashboard version information.

</details>

## 2. Usage

<details id="21-start-monitoring" open>
<summary>2.1 Prefix your command with netinspect</summary>

```sh
netinspect curl -I https://example.com
netinspect python app.py
netinspect run -- ./my-command --help
```

The default `preload` mode works with dynamically linked programs. For statically linked programs, including many Go executables, use `ptrace`:

```sh
netinspect --mode ptrace -- ./my-go-program
```

To monitor commands launched from an interactive shell, pass the shell explicitly:

```sh
netinspect -- "$SHELL"
```

**Running without arguments only prints help.** Only the plain `netinspect command args...` shortcut can omit `--`. When using `run` or netinspect options, place `--` before the target command. All subsequent arguments are passed through unchanged.

```sh
netinspect --mode observe --keep-alive 10m -- python app.py
netinspect --open-browser=false --port 0 -- curl -I https://example.com
netinspect --help
```

</details>

<details id="22-open-the-dashboard">
<summary>2.2 Inspect connections in your browser</summary>

Open the dashboard URL printed in the terminal. The default address is `127.0.0.1:17890`; occupied ports are incremented automatically. Use `--port 0` to let the OS select an available port. On a desktop, netinspect attempts to open a browser by default; disable this with `--open-browser=false`.

- Switch between all, active, and closed records.
- Search destinations, processes, IPs, SNI, or DNS answers. Press `/` to focus search.
- Sort through column headers or the sort menu, and choose column visibility and order in settings.
- Click a record for process, destination, timing, traffic, TLS, or DNS details. Available fields depend on the mode.
- Pausing the dashboard only pauses page updates; monitoring and recording continue.

Each run has its own session, dashboard port, and stop token. Multiple commands can be monitored concurrently.

</details>

<details id="23-exit-and-retention">
<summary>2.3 Keep records after exit or close the dashboard early</summary>

When the target command exits, the terminal prints its result and the dashboard expiry time. netinspect stays in the foreground for **30 minutes** by default, allowing you to inspect existing records, then returns the target command's exit code.

```sh
# Retain the dashboard for 10 minutes after the target exits
netinspect --keep-alive 10m -- curl -I https://example.com

# Close immediately after the target exits
netinspect --keep-alive 0 -- curl -I https://example.com
```

During retention, use the dashboard shutdown button, press Ctrl+C, or copy the stop command printed in the terminal:

```sh
netinspect stop --url http://127.0.0.1:17890 --token TOKEN_FROM_TERMINAL
```

Dashboard shutdown and `stop` are rejected while the target is still running. Closing the dashboard releases the session's in-memory records; there is no cross-session history.

</details>

<details id="24-configuration">
<summary>2.4 Configure defaults and the memory budget</summary>

Configuration is loaded in this order, with later values taking precedence:

1. `$XDG_CONFIG_HOME/netinspect/config.json`, or `~/.config/netinspect/config.json` when XDG is unset.
2. `.netinspect.json` in the current directory.
3. Command-line options.

Create configuration files manually. All fields are optional. Example `.netinspect.json`:

```json
{
  "mode": "preload",
  "listen": "127.0.0.1:17890",
  "keep_alive": "30m",
  "open_browser": true,
  "memory_mb": 128
}
```

`--config FILE` replaces automatic discovery and loads only the specified file. Missing explicit files, unknown fields, and invalid formats produce errors. Within one configuration layer, `port` overrides the port in `listen`.

```sh
netinspect --config ./netinspect.json -- python app.py
netinspect --memory-mb 64 -- python app.py
```

`memory_mb` is a **record storage budget**, not a total process memory limit. Proxy buffers and the Go runtime use additional memory. Each record reserves a conservative 8 KiB, allowing up to 16,384 records by default. At the limit, new records are rejected without evicting history. Existing connections continue to update, and the proxy and target keep running.

</details>

## 3. Mode comparison

| Mode | How it works | Best suited for | DNS queries | Requirements and limits |
| --- | --- | --- | --- | --- |
| `preload` (default) | `LD_PRELOAD` intercepts connections and forwards them through a local proxy | Dynamically linked command-line programs | Not recorded | Usually no root required; ineffective for static binaries |
| `ptrace` | Rewrites the target's `connect` system calls | Static / Go executables | Not recorded | Linux x86_64 only; system policy must permit ptrace |
| `netns` | Separate network namespace, TCP redirection, and a DNS forwarder | TCP and DNS monitoring together | Questions and answers | Requires root, namespace, and iptables permissions |
| `observe` | Polls TCP connections in `/proc` | Connection overview without forwarding | Not recorded | Does not rewrite target connections; visibility depends on `/proc` permissions and polling intervals |

<details>
<summary>Using netns</summary>

The host needs `ip` (iproute2), `iptables`, and `sysctl`. Restoring the target user after sudo also requires `setpriv` (util-linux).

```sh
sudo "$HOME/.local/bin/netinspect" --mode netns -- curl -I https://example.com
sudo "$HOME/.local/bin/netinspect" --mode netns --user alice -- python app.py
```

When launched through sudo, the monitor creates the namespace as root and runs the target as the original sudo user by default. `--user` selects a username or UID. A direct root invocation without a selected user runs the target as root. `--user` is only supported in `netns` mode.

</details>

<details>
<summary>Record scope and visibility</summary>

- TCP details depend on the mode. `observe` records connection endpoints and observed start/end times, without success/failure classification or byte counts. Short connections may be missed.
- `preload` has no effect on static binaries, so their connections will not appear in that mode.
- TLS metadata is extracted from visible ClientHello messages, limited to SNI / ALPN. TLS timing is a passive approximation of the handshake round trip.
- DNS records depend on the `netns` DNS forwarder. Application-level encrypted DNS does not automatically appear as ordinary DNS records.
- There is no general UDP monitoring, HTTP request body parsing, HTTPS decryption, or network content storage.

</details>

## 4. Development and releases

<details>
<summary>Local validation</summary>

```sh
make -C modes/preload
go test ./...
go vet ./...
sh scripts/build.sh -o /tmp/netinspect
python3 scripts/cli-smoke.py /tmp/netinspect
```

The CLI smoke test only uses local loopback. It covers argument forwarding, target exit codes, dashboard retention, concurrent ports, and stop isolation. Runtime verification of `netns` requires root and network namespace permissions.

</details>

<details>
<summary>Publish a Release and update the Homebrew tap</summary>

Pushing a new version tag triggers the [Release workflow](.github/workflows/release.yml): tests, Linux amd64 build, CLI smoke, archive and checksum generation, GitHub Release publication, and Actions Artifacts upload.

```sh
git tag v0.1.2
git push origin v0.1.2
```

Stable tags use `v1.2.3` or `1.2.3`. Tags containing `-`, such as `v1.2.3-rc.1`, create prereleases and skip the Homebrew update. Project versions come from Git tags; the `go` directive in `go.mod` declares the minimum Go toolchain version.

Homebrew updates use `HOMEBREW_TAP_TOKEN` in the **netinspect repository's** Actions Repository secrets. It needs **Contents: Read and write** access to `ctxinf/homebrew-tap`, including permission to push to its default branch. Release publication uses the workflow's built-in `GITHUB_TOKEN`.

To retry a publication, choose Actions → Release → Run workflow and enter an existing tag. Release-only scripts live in `.github/workflows`; the installation entry point is [install.sh](install.sh) at the repository root.

</details>

## License

[MIT](LICENSE). The preload and ptrace interception implementations are original code and do not use graftcp / proxychains code.
