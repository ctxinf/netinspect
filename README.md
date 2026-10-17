# netinspect (Phase 1)

Linux 进程级网络连接监控。**纯连接级元数据**：五元组、进程、耗时、流量、
结果、SNI/ALPN、DNS 查询。**不做 MITM、不解密、不看任何内容**。纯内存存储，
进程退出记录即丢弃。

## 构建

```bash
make -C modes/preload        # 编出 LD_PRELOAD 的 .so (Go embed 需要)
export PATH=$HOME/workspace/toolchains/go/bin:$PATH
go build ./... && go vet ./...
go build -o netinspect ./cmd/netinspect
```

## 用法

```bash
netinspect -- <command> [args...]                                  # 最简, 默认 observe
netinspect --mode <preload|ptrace|netns|observe> -- <command> ...  # 简写, 直接指定模式
netinspect run --mode <preload|ptrace|netns|observe> [--listen 127.0.0.1:17890] -- <command> [args...]
```

| 模式 | 原理 | TCP | DNS | UDP | 说明 |
|---|---|---|---|---|---|
| `preload` | LD_PRELOAD 拦截 `connect` → SOCKS5 本地代理 | ✅ | ❌ 不可见 | ❌ | 仅动态链接程序；静态链接不生效 |
| `ptrace` | ptrace 改写 `connect` syscall → 透明代理 | ✅ | ❌ 不可见 | ❌ | x86_64；静态/Go 程序可用 |
| `netns` | 独立 netns + iptables REDIRECT + DNS 转发器 | ✅ | ✅ 记录查询 | ❌ | 需 root |
| `observe` | /proc 轮询，不拦截 | ✅ 元数据 | ❌ | ❌ | 零侵入 |

`--mode` 必须手动指定，无默认值、无自动选择。

## 诚实边界

- `preload` 对静态链接二进制无效（`LD_PRELOAD` 不被加载），此时连接**不会**出现在面板里。
- `preload`/`ptrace` 不拦截 DNS：应用直连解析，面板看不到 DNS 查询。
- UDP 在所有模式下都不覆盖。
- `observe` 只能看到 TCP 连接的起止与远端，不知道成功/失败细节，没有流量字节数。
- TLS 只解析 ClientHello 的 SNI/ALPN（回答"连了哪个域名"），绝不解密。
- `tls_ms` 是被动测量的握手往返近似值（ClientHello 发出 → 服务端首字节到达）。
- 单次运行、无历史：dashboard 只展示当前 session，进程退出即清空。

## 防递归

- `preload`/`ptrace`：发往 127.0.0.1/`::1` 且端口为代理/dash 端口的连接会被拦截器放行。
- `netns`：代理的出站 socket 打 `SO_MARK=0x1`，ns 内 iptables 优先放行 mark 0x1 的 TCP，
  避免 REDIRECT 回环。

## 许可证

MIT。拦截库为原创实现，未使用 graftcp/proxychains 代码。
