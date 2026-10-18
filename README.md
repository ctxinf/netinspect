<p align="center"><img src="assets/favicon.png" width="96" height="96" alt="netinspect icon" /></p>
<h1 align="center">netinspect</h1>
<p align="center">English · <a href="README.zh.md">中文</a></p>

`netinspect -- COMMAND ARGS` **launches a command, then lets you inspect the process's network connections in the Web dashboard.**

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

## Usage

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
brew install ctxinf/tap/netinspect
```

Homebrew selects the glibc package for Intel or ARM Linux automatically. For musl systems such as Alpine, use the install script.

### 1.3 Manual download

Download the archive matching your architecture and libc from [Releases](https://github.com/ctxinf/netinspect/releases/latest).

### 1.4 Build from source

Requires Linux, Go **1.27.2 or newer**, a C compiler, and `make`. Build with:

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

| Mode | Compatibility | Best suited for | DNS queries | Requirements and limits |
| --- | --- | --- | --- | --- |
| `preload` (default) | ⭐⭐ | Dynamically linked command-line programs | No | Usually no root required; ineffective for static binaries; the library must match the target's architecture and libc and meet its required glibc version |
| `ptrace` | ⭐⭐⭐ | Static / Go executables | No | Linux x86_64 only; system policy must permit ptrace |
| `netns` | ⭐⭐⭐⭐ | TCP and DNS monitoring together | Yes | Requires root, namespace, and iptables permissions |
| `observe` | ⭐⭐⭐⭐⭐ | Connection overview without forwarding | No | Does not rewrite target connections; visibility depends on `/proc` permissions and polling intervals |

Stars indicate the relative range of compatible target programs, with more stars meaning broader compatibility. They do not measure recording completeness; permissions and runtime environment still apply.

How each mode works:

- `preload`: intercepts connections through `LD_PRELOAD` and forwards them through a local proxy.
- `ptrace`: rewrites the target's `connect` system calls.
- `netns`: uses a separate network namespace, TCP redirection, and DNS forwarding.
- `observe`: polls TCP connections in `/proc`.

<details>
<summary>Using netns</summary>

The host needs `ip` (iproute2), `iptables`, and `sysctl`. Restoring the target user after sudo also requires `setpriv` (util-linux).

```sh
sudo "$HOME/.local/bin/netinspect" --mode netns -- curl -I https://example.com
sudo "$HOME/.local/bin/netinspect" --mode netns --user alice -- python app.py
```

When launched through sudo, the monitor creates the namespace as root and runs the target as the original sudo user by default. `--user` selects a username or UID. A direct root invocation without a selected user runs the target as root. `--user` is only supported in `netns` mode.

</details>
