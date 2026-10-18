<p align="center"><img src="assets/favicon.png" width="96" height="96" alt="netinspect icon" /></p>
<h1 align="center">netinspect</h1>
<p align="center"><a href="README.md">中文</a> · English</p>

<p align="center">`netinspect -- COMMAND ARGS` Inspect a process's network connections</p>

<image src="assets/demo.gif"/>

- Wrap and launch a command directly from the CLI.
- A Web dashboard similar to MetacubeX and Zashboard.
- Choose from four modes based on the target program and available permissions: `preload`, `ptrace`, `netns`, and `observe`.

**Use cases:**
- Inspect a program's network connections.
- Combine **CLI launch + Web inspection** to simplify analysis that would otherwise require manual tcpdump, packet capture, or MITM setup.

**What is not included:**
- Linux only; no Windows or macOS version.
- No automatic mode selection; choose a mode explicitly.
- No persistence; records stay in memory and are released on shutdown.
- No MITM, TLS decryption, or storage of request/response bodies.
- No nested use with `proxychains4` or `graftcp`.

**Limitations:**
1. Many nonstandard binaries cannot be used directly.
2. Some architectures cannot be fully analyzed, such as client/daemon-server setups.

```sh
# 0. Shortcut: add the alias to ~/.bashrc or ~/.zshrc
alias ni=netinspect
ni curl -I https://example.com

# 1. Basic usage: the target command and its arguments follow --; preload is the default
netinspect -- curl -I https://example.com

# 2. Select a mode: use ptrace for static binaries, such as Go programs
netinspect --mode ptrace -- ./my-go-program

# 3. Start an interactive shell: monitor its child processes; type exit to leave
netinspect -- "$SHELL"

# 4. Helper commands: initialize configuration and read bundled agent guidance
netinspect init-config
netinspect skills list
netinspect skills get core --full
```

## Installation

### 1.1 Install script

```sh
curl -fsSL https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh
```

### 1.2 Homebrew

```sh
brew install ctxinf/homebrew-tap
```

### 1.3 Manual download

Sign in to GitHub and download `netinspect_linux_amd64.tar.gz` from [Releases](https://github.com/ctxinf/netinspect/releases/latest).

### 1.4 Build from source

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

Build `modes/preload/libnetinspect.so` before compiling Go so it can be embedded in the binary. `scripts/build.sh` injects the nearest tag and current commit for the CLI and dashboard version information.

## Four modes

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
