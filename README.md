<p align="center"><img src="assets/favicon.png" width="96" height="96" alt="netinspect icon" /></p>
<h1 align="center">netinspect</h1>
<p align="center">中文 · <a href="README.en.md">English</a></p>

<p align="center">`netinspect -- COMMAND ARGS` 查看进程的网络连接情况</p>

<image src="assets/demo.gif"/>

- CLI一键快速包裹启动
- 类似 MetacubeX, Zashboard 一样的web面板。
- 提供 `preload`、`ptrace`、`netns`、`observe` 四种模式，按目标程序和权限选择。

**使用场景**:
- 查看某个程序的网络连接
- 通过一键**CLI运行+web面板查看**方便分析过程, 代替手工tcpdump, 手工抓包, 手工mitm.


**没有什么:**
- 仅linux版本, 没有window, macos版
- 没有自动模式, 必须手动选择和制定模式
- 不持久化, 记录只保存在内存中, 关闭后释放数据。
- 不做 MITM、不解密 TLS、不保存请求或响应正文。
- 不支持嵌套`proxychains4`, `graftcp` 使用。

**劣势缺陷:**
1. 很多非标准binary程序无法直接使用
2. 很多架构无法完整分析, 比如 Client/Daemon-Server 模式


```sh
# 0. 快捷使用：可将 alias 加入 ~/.bashrc 或 ~/.zshrc
alias ni=netinspect
ni curl -I https://example.com

# 1. 基础使用：-- 后为目标命令及其参数，默认使用 preload 模式
netinspect -- curl -I https://example.com

# 2. 指定模式：静态链接程序（如 Go 程序）可使用 ptrace
netinspect --mode ptrace -- ./my-go-program

# 3. 进入交互 shell：监控其中启动的子进程，输入 exit 退出
netinspect -- "$SHELL"

# 4. 辅助命令：初始化配置、查看随程序附带的 Agent 使用指南
netinspect init-config
netinspect skills list
netinspect skills get core --full
```

## 安装

### 1.1 通过脚本安装

```sh
curl -fsSL https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh
```

### 1.2 Homebrew

```sh
brew install ctxinf/homebrew-tap
```

### 1.3 直接下载安装

登录 GitHub 后，从 [Releases](https://github.com/ctxinf/netinspect/releases/latest) 下载 `netinspect_linux_amd64.tar.gz` 

### 1.4 从源码安装

需要 Linux、Go **1.27.2 或更新版本**、C 编译器和 `make`。先通过 GitHub CLI 或 Git credential helper 配置私有仓库访问，再构建：

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

必须先构建 `modes/preload/libnetinspect.so`，Go 编译时会将它嵌入 binary。`scripts/build.sh` 写入最近的 tag 和当前 commit，CLI 与面板会显示对应版本信息。

## 四种模式

| 模式 | 工作方式 | 适用场景 | DNS 查询 | 权限与限制 |
| --- | --- | --- | --- | --- |
| `preload`（默认） | `LD_PRELOAD` 拦截连接，通过本地代理转发 | 动态链接的命令行程序 | 不记录 | 通常无需 root；静态链接程序不生效 |
| `ptrace` | 改写目标进程的 `connect` 系统调用 | 静态链接 / Go 程序 | 不记录 | 仅 Linux x86_64，需系统允许 ptrace |
| `netns` | 独立网络命名空间、TCP 重定向和 DNS 转发 | 同时查看 TCP 与 DNS | 记录查询与应答 | 需要 root、namespace 和 iptables 权限 |
| `observe` | 轮询 `/proc` 中的 TCP 连接 | 无需转发的连接概览 | 不记录 | 不改写目标连接；可见性受 `/proc` 权限与轮询间隔影响 |

<details>
<summary>使用 netns 模式</summary>

宿主机需要 `ip`（iproute2）、`iptables`、`sysctl`；通过 sudo 恢复目标用户身份时还需要 `setpriv`（util-linux）。

```sh
sudo "$HOME/.local/bin/netinspect" --mode netns -- curl -I https://example.com
sudo "$HOME/.local/bin/netinspect" --mode netns --user alice -- python app.py
```

通过 sudo 启动时，监控进程以 root 创建网络命名空间，目标命令默认恢复为 sudo 前的用户；`--user` 可指定用户名或 UID。直接以 root 启动且未指定用户时，目标命令仍以 root 运行。`--user` 仅适用于 `netns`。

</details>

<details>
<summary>记录范围与可见性</summary>

- TCP 连接详情取决于模式。`observe` 只记录连接起止与端点，不提供连接成功 / 失败判断或流量字节数，也可能漏掉短连接。
- `preload` 对静态链接程序不生效，这类程序的连接不会出现在该模式的面板中。
- TLS 信息来自可见的 ClientHello，仅提取 SNI / ALPN；TLS 耗时是握手往返的被动近似值。
- DNS 记录依赖 `netns` 的 DNS 转发器；应用内加密 DNS 不会自动变成普通 DNS 查询记录。
- 不提供通用 UDP 监控，也不解析 HTTP 请求正文、解密 HTTPS 或保存网络内容。

</details>
