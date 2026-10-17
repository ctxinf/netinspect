# netinspect (Phase 1)

Linux 进程级网络连接监控。**纯连接级元数据**：五元组、进程、耗时、流量、
结果、SNI/ALPN、DNS 查询。**不做 MITM、不解密、不看任何内容**。纯内存存储，
面板关闭后记录丢弃。

## 构建

```bash
make -C modes/preload        # 编出 LD_PRELOAD 的 .so (Go embed 需要)
go build ./... && go vet ./...
go build -o netinspect ./cmd/netinspect
```

## 用法

### Release 与 Homebrew

推送 tag 后，GitHub Actions 自动运行测试、构建 Linux amd64 binary，并发布包含
`netinspect_linux_amd64.tar.gz` 和 `SHA256SUMS` 的 GitHub Release。
binary 已嵌入 preload 库；该库在 Ubuntu 22.04 上编译，需要 glibc 2.35 或更新版本。

正式版本使用 `v1.2.3` 或 `1.2.3` 格式。带 `-` 的 tag（如 `v1.2.3-rc.1`）
发布为 prerelease，不更新 Homebrew。正式发布后自动更新 `ctxinf/homebrew-tap` 的
`Formula/netinspect.rb`，相同 tag 的工作流可重跑以恢复上传或 tap 更新。

首次使用前，在本仓库的 Actions secrets 中配置 `HOMEBREW_TAP_TOKEN`：
使用可访问 `ctxinf/homebrew-tap` 且具有 **Contents: Read and write** 权限的
fine-grained PAT，并确保允许向 tap 的默认分支直接推送。Release 使用自带的
`GITHUB_TOKEN`，无需另配。

```bash
git tag v0.1.0
git push origin v0.1.0

# Linux x86_64 上安装
brew install ctxinf/tap/netinspect

# 或下载并校验最新 Release，安装到 ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh

# 指定版本和安装目录（目录需要当前用户有写入权限）
curl -fsSL https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | \
  NETINSPECT_VERSION=v0.1.0 NETINSPECT_INSTALL_DIR="$HOME/.local/bin" sh
```

以上匿名安装要求仓库公开。私有仓库需先导出具有仓库 Contents 读取权限的
`GH_TOKEN`（安装时还需要 `python3`），再执行：

```bash
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
  https://raw.githubusercontent.com/ctxinf/netinspect/main/install.sh | sh
```

如果 tag 推送未触发，或需要重新发布，在 Actions → Release → Run workflow 中填写
现有 tag。构建产物也会保存在该次运行的 Artifacts 中。

### 运行

```bash
netinspect                                          # 默认 preload，进入 $SHELL
netinspect curl -I https://example.com                # 省略 run 和 --
netinspect run -- ./my-command --help                 # 命令后的参数全部透传
netinspect --mode observe -- python app.py
netinspect --port 17890 --keep-alive 10m -- ./my-command
netinspect --config ./netinspect.json -- ./my-command
netinspect --help
```

目标命令结束后，会打印执行结果和面板关闭时间；面板默认继续运行 **30 分钟**，
可查看本次运行的全部内存记录。netinspect 在此期间保持前台运行，退出时保留目标命令的退出码。
复制终端中打印的 `netinspect stop --url … --token …` 命令，或在网页点击 **结束 Server**，
即可提前关闭当前实例。目标仍在运行时不允许关闭面板。保留期间也可按 Ctrl+C 退出。
`--keep-alive 0` 可在目标结束后立即关闭。端口占用时逐一递增直到找到可用端口；
多个实例各自保存数据、使用各自的停止令牌，互不影响。`--port 0` 由系统分配端口。

### 配置文件

自动读取以下文件，后者覆盖前者，命令行参数优先：

1. `$XDG_CONFIG_HOME/netinspect/config.json`（未设置 XDG 时为 `~/.config/netinspect/config.json`）。
2. 当前工作目录 `.netinspect.json`。

`--config FILE` 使用显式文件替代自动发现；文件缺失、未知字段或格式错误会报错。
所有字段均可省略。`port` 覆盖同一层的 `listen` 端口，`keep_alive` 使用 Go 时长格式（例如 `30m`、`1h`、`10s`）。

```json
{
  "mode": "preload",
  "listen": "127.0.0.1:17890",
  "keep_alive": "30m"
}
```

只有无子命令、无 netinspect 选项的 `netinspect command args...` 快捷形式可省略 `--`。
使用 `run` 或任何 netinspect 选项且指定目标命令时，必须添加 `--`；省略目标命令仍启动 Shell。
命令后的参数全部属于目标程序。执行名称为 `run`、`stop`、`help` 的程序时，
使用 `netinspect -- <command>` 或程序的完整路径以避免与子命令冲突。

| 模式 | 原理 | TCP | DNS | UDP | 说明 |
|---|---|---|---|---|---|
| `preload` | LD_PRELOAD 拦截 `connect` → SOCKS5 本地代理 | ✅ | ❌ 不可见 | ❌ | 仅动态链接程序；静态链接不生效 |
| `ptrace` | ptrace 改写 `connect` syscall → 透明代理 | ✅ | ❌ 不可见 | ❌ | x86_64；静态/Go 程序可用 |
| `netns` | 独立 netns + iptables REDIRECT + DNS 转发器 | ✅ | ✅ 记录查询 | ❌ | 需 root |
| `observe` | /proc 轮询，不拦截 | ✅ 元数据 | ❌ | ❌ | 零侵入 |

默认模式为 `preload`，可以通过配置文件或 `--mode` 切换。

## 诚实边界

- `preload` 对静态链接二进制无效（`LD_PRELOAD` 不被加载），此时连接**不会**出现在面板里。
- `preload`/`ptrace` 不拦截 DNS：应用直连解析，面板看不到 DNS 查询。
- UDP 在所有模式下都不覆盖。
- `observe` 只能看到 TCP 连接的起止与远端，不知道成功/失败细节，没有流量字节数。
- TLS 只解析 ClientHello 的 SNI/ALPN（回答"连了哪个域名"），绝不解密。
- `tls_ms` 是被动测量的握手往返近似值（ClientHello 发出 → 服务端首字节到达）。
- 单次运行、无持久历史：dashboard 展示当前 session，目标结束后保留至面板关闭。

## 防递归

- `preload`/`ptrace`：发往 127.0.0.1/`::1` 且端口为代理/dash 端口的连接会被拦截器放行。
- `netns`：代理的出站 socket 打 `SO_MARK=0x1`，ns 内 iptables 优先放行 mark 0x1 的 TCP，
  避免 REDIRECT 回环。

## 验证

```bash
go test ./...
go vet ./...
go build -o /tmp/netinspect ./cmd/netinspect
python3 scripts/cli-smoke.py /tmp/netinspect
```

CLI smoke 仅使用本机 loopback，覆盖参数透传、默认 Shell、延时关闭、多实例及停止隔离。
netns 运行验证需要 root 和 namespace/iptables 权限。

## 许可证

MIT。拦截库为原创实现，未使用 graftcp/proxychains 代码。
