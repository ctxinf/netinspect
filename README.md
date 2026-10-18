<p align="center"><img src="assets/favicon.png" width="96" height="96" alt="netinspect icon" /></p>
<h1 align="center">netinspect</h1>
<p align="center">中文 · <a href="README.en.md">English</a></p>

<p align="center">面向 Linux 命令行程序的进程级网络监控工具，在浏览器里查看一次运行的网络连接。</p>

- 在原命令前加上 `netinspect` 即可使用，CLI 启动监控和 Web 面板。
- 查看连接目标、进程、连接耗时、上下行流量、结果，以及可见的 TLS SNI / ALPN；`netns` 模式还可记录 DNS 查询与应答。
- Web 面板实时更新，支持状态筛选、搜索、排序、分页、列设置、连接详情和明暗主题。
- 提供 `preload`、`ptrace`、`netns`、`observe` 四种模式，按目标程序和权限选择。
- Go 开发，面板和 preload 拦截库内嵌在 binary 中，无需单独部署 Web 服务。
- 记录只保存在内存中，默认预算 **128 MiB**；命令结束后面板默认保留 **30 分钟**，关闭后释放数据。
- 仅记录连接元数据，不做 MITM、不解密 TLS、不保存请求或响应正文。

## 目录

- [1. 安装](#1-安装)
  - [1.1 通过脚本安装](#11-通过脚本安装)
  - [1.2 直接下载安装](#12-直接下载安装)
  - [1.3 Homebrew](#13-homebrew)
  - [1.4 从源码安装](#14-从源码安装)
- [2. 使用](#2-使用)
  - [2.1 启动监控](#21-启动监控)
  - [2.2 查看面板](#22-查看面板)
  - [2.3 结束与保留记录](#23-结束与保留记录)
  - [2.4 配置](#24-配置)
- [3. 模式对比](#3-模式对比)
- [4. 开发与发布](#4-开发与发布)
- [许可证](#许可证)

## 1. 安装

当前预编译包支持 **Linux x86_64 / amd64**。默认 `preload` 模式使用 glibc 动态库，发布包在 Ubuntu 22.04 上构建，要求 glibc 2.35 或更新版本；其他系统环境可尝试从源码构建。

仓库目前为私有，下载脚本、源码和 Release 均需要有仓库读取权限的 GitHub 账号或 Token。以下 `GH_TOKEN` 应具有 `ctxinf/netinspect` 的 **Contents: Read** 权限。

<details id="11-通过脚本安装" open>
<summary>1.1 通过脚本安装</summary>

无需安装 Go。准备 `curl`、`tar`、`sha256sum` 和 `python3`，将有仓库读取权限的 Token 导出为 `GH_TOKEN` 后执行：

```sh
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
  https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
netinspect --version
```

脚本下载最新正式 Release，校验 SHA256 后安装到 `~/.local/bin`。将上面的 `PATH` 设置加入 Shell 配置，后续终端即可直接使用。

也可先下载脚本，再指定版本和安装目录：

```sh
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
  https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh -o /tmp/netinspect-install.sh
NETINSPECT_VERSION=v0.1.1 NETINSPECT_INSTALL_DIR="$HOME/.local/bin" \
  sh /tmp/netinspect-install.sh
```

`NETINSPECT_VERSION` 默认为 `latest`，指定时使用完整 tag；`NETINSPECT_INSTALL_DIR` 需要当前用户有写入权限。更新时重新运行脚本即可。

</details>

<details id="12-直接下载安装">
<summary>1.2 直接下载安装</summary>

登录 GitHub 后，从 [Releases](https://github.com/ctxinf/netinspect/releases/latest) 下载 `netinspect_linux_amd64.tar.gz` 和 `SHA256SUMS`，放到同一目录：

```sh
sha256sum -c SHA256SUMS
tar -xzf netinspect_linux_amd64.tar.gz
mkdir -p "$HOME/.local/bin"
install -m 755 netinspect "$HOME/.local/bin/netinspect"
export PATH="$HOME/.local/bin:$PATH"
netinspect --version
```

压缩包包含 `netinspect`、README 和许可证；preload 库和 Web 面板已内嵌，无需额外复制。

</details>

<details id="13-homebrew">
<summary>1.3 Homebrew</summary>

正式发布会自动将 `Formula/netinspect.rb` 同步到 [ctxinf/homebrew-tap](https://github.com/ctxinf/homebrew-tap)，目前提供 Linux x86_64 的 binary formula。

当前 formula 的下载地址指向私有 Release，尚未配置 Homebrew 的私有资产下载认证；仅添加 tap 不能完成匿名安装。当前请使用上面的 Token 安装脚本或手动下载方式。

</details>

<details id="14-从源码安装">
<summary>1.4 从源码安装</summary>

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

</details>

## 2. 使用

<details id="21-启动监控" open>
<summary>2.1 在原命令前加上 netinspect</summary>

```sh
netinspect curl -I https://example.com
netinspect python app.py
netinspect run -- ./my-command --help
```

默认使用 `preload` 模式，适合动态链接程序。静态链接程序（例如常见的 Go binary）可选择 `ptrace`：

```sh
netinspect --mode ptrace -- ./my-go-program
```

要监控一个交互式 Shell 中启动的命令，显式传入 Shell：

```sh
netinspect -- "$SHELL"
```

**不带参数运行只显示帮助。** 仅 `netinspect command args...` 的快捷形式可省略 `--`；使用 `run` 或 netinspect 选项时，目标命令前必须添加 `--`。分隔符后的参数全部原样传给目标程序。

```sh
netinspect --mode observe --keep-alive 10m -- python app.py
netinspect --open-browser=false --port 0 -- curl -I https://example.com
netinspect --help
```

可将 `alias ni=netinspect` 加入 `~/.bashrc` 或 `~/.zshrc`，然后使用 `ni curl -I https://example.com`。
CLI 帮助和诊断统一为英文；终端中帮助标题带颜色，重定向、`NO_COLOR` 或 `TERM=dumb` 时不输出 ANSI 颜色。

Agent 指导内嵌在当前版本的 binary 中，接口参考 [agent-browser skills](https://github.com/vercel-labs/agent-browser/blob/main/docs/src/app/skills/page.mdx)：

```sh
netinspect skills list
netinspect skills get core
netinspect skills get core --full
```


</details>

<details id="22-查看面板">
<summary>2.2 在浏览器中查看连接与详情</summary>

启动后查看终端打印的面板地址。默认监听 `127.0.0.1:17890`，端口占用时自动递增；`--port 0` 使用系统分配的空闲端口。有桌面环境时默认尝试打开浏览器，可通过 `--open-browser=false` 关闭。

- 在「全部」「活动」「已关闭」之间切换，查看连接状态。
- 搜索目标、进程、IP、SNI 或 DNS 应答；按 `/` 聚焦搜索框。
- 点击表头或排序菜单调整排序，通过列设置选择显示字段与顺序。
- 点击记录查看进程、目标、耗时、流量、TLS 或 DNS 详情；字段可见性取决于监控模式。
- 暂停按钮只暂停页面刷新，后台监控和记录继续运行。

每次运行都有独立会话、面板端口和停止令牌，可以同时监控多个命令。禁止嵌套运行 netinspect 采集，Shell 套壳也会进行检测。

面板支持英语、简体中文、西班牙语、法语、德语、日语和葡萄牙语，首次根据浏览器语言偏好选择；切换语言后通过 cookie 保存一年。

</details>

<details id="23-结束与保留记录">
<summary>2.3 命令结束后继续查看，或提前关闭面板</summary>

目标命令结束后，终端会打印执行结果和面板关闭时间。netinspect 默认继续在前台运行 **30 分钟**，供你查看已有记录，最后保留目标程序的退出码。

```sh
# 目标结束后保留 10 分钟
netinspect --keep-alive 10m -- curl -I https://example.com

# 目标结束后立即关闭
netinspect --keep-alive 0 -- curl -I https://example.com
```

保留期间可点击面板的关闭服务按钮、按 Ctrl+C，或复制终端打印的停止命令：

```sh
netinspect stop --url http://127.0.0.1:17890 --token TOKEN_FROM_TERMINAL
```

目标仍在运行时，不允许通过面板或 `stop` 关闭服务。面板关闭后，本次内存记录释放，不保留跨会话历史。

</details>

<details id="24-配置">
<summary>2.4 调整默认配置与内存预算</summary>

自动读取以下配置，优先级从低到高：

1. `$XDG_CONFIG_HOME/netinspect/config.json`，未设置 XDG 时为 `~/.config/netinspect/config.json`。
2. 当前目录 `.netinspect.json`。
3. 命令行选项。

`netinspect init-config` 创建默认用户级配置，不覆盖已有文件。`netinspect --help` 显示用户和当前目录配置的绝对路径与存在状态。所有字段均可省略。示例 `.netinspect.json`：

```json
{
  "mode": "preload",
  "listen": "127.0.0.1:17890",
  "keep_alive": "30m",
  "open_browser": true,
  "memory_mb": 128,
  "upstream_proxy": null
}
```

使用 `--config FILE` 时只读取指定文件，替代自动发现；文件缺失、未知字段或格式错误会报错。同一层配置中的 `port` 会覆盖 `listen` 的端口。

```sh
netinspect --config ./netinspect.json -- python app.py
netinspect --memory-mb 64 -- python app.py
```

`memory_mb` 是**记录存储预算**，不是进程总内存上限；代理缓冲区和 Go 运行时另外占用内存。每条记录保守预留 8 KiB，默认最多保留 16,384 条。达到预算后停止新增记录，不淘汰已有历史；已有连接继续更新，代理和目标程序继续运行。

</details>

### 上游代理

```sh
netinspect --upstream-proxy http://127.0.0.1:3128 -- curl -I https://example.com
netinspect --upstream-proxy socks5h://127.0.0.1:1080 -- curl -I https://example.com
```

默认配置中的 `"upstream_proxy": null` 表示未设置上游代理，未被其他配置覆盖时使用直连；空字符串 `""` 可明确禁用此前配置的代理。填写 `"upstream_proxy": "http://127.0.0.1:3128"` 即可启用上游代理。
支持 `http`、`https`、`socks5`、`socks5h`，以及 URL 中的 `user:password@` 认证（HTTP Basic / SOCKS5 用户名密码）；HTTPS 代理使用系统信任的证书。路由记录和启动提示不包含认证信息，上游失败不会回退为直连。

此功能代理 preload、ptrace、netns 的 TCP，observe 模式会拒绝该选项；DNS/UDP 不走隧道。
`socks5` 本地解析域名，`socks5h` 和 HTTP(S) 将可用的目标域名交给代理；应用在拦截前已经完成解析时，代理仍会收到 IP。
netns 内必须能访问上游地址，不能直接将宿主机回环地址当作命名空间内地址使用。
此选项不会读取环境代理变量来自动选择上游，也不会移除目标应用自己的代理配置，因此可能形成代理链。


## 3. 模式对比

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

## 4. 开发与发布

<details>
<summary>本地验证</summary>

```sh
make -C modes/preload
go test ./...
go vet ./...
node scripts/test-i18n.cjs # Node.js 18+
sh scripts/build.sh -o /tmp/netinspect
python3 scripts/cli-smoke.py /tmp/netinspect
```

CLI smoke 仅使用本机 loopback，覆盖参数透传、命令退出码、面板保留、并发端口和实例停止隔离。涉及 `netns` 的运行验证需要额外的 root 和网络命名空间权限。

</details>

<details>
<summary>发布 Release 与更新 Homebrew tap</summary>

推送新的版本 tag 即可触发 [Release 工作流](.github/workflows/release.yml)：测试、构建 Linux amd64 binary、运行 CLI smoke、生成压缩包与 SHA256，然后发布 GitHub Release 和 Actions Artifacts。

```sh
git tag v0.1.2
git push origin v0.1.2
```

正式版使用 `v1.2.3` 或 `1.2.3` 格式；带 `-` 的 tag（如 `v1.2.3-rc.1`）发布为 prerelease，不更新 Homebrew tap。版本来自 Git tag，`go.mod` 中的 `go` 字段声明最低 Go 工具链版本。

Homebrew 更新使用 **netinspect 仓库** Actions Repository secrets 中的 `HOMEBREW_TAP_TOKEN`，需对 `ctxinf/homebrew-tap` 有 **Contents: Read and write** 权限，并允许直接推送默认分支。Release 使用工作流自带的 `GITHUB_TOKEN`。

需要补发或重试时，在 Actions → Release → Run workflow 中填入现有 tag。发布专用脚本放在 `.github/workflows` 中，安装入口为根目录的 [install.sh](install.sh)。

</details>

## 许可证

[MIT](LICENSE)。preload 与 ptrace 拦截实现为原创代码，未使用 graftcp / proxychains 代码。
