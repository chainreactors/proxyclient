# 架构

## 项目结构

```
proxyclient (核心)
├── 内置协议: direct, reject, blackhole, http(s), socks4/4a/5/5+tls
├── 可选协议 (build tag):
│   └── proxyclient_ssh → SSH
│
├── webshell/ — Webshell 隧道代理
│   ├── suo5/    (build tag: suo5)    — 实现 + 注册，自包含
│   └── neoreg/  (build tag: neoreg)  — 实现 + 注册，自包含
│
├── extra/ — 扩展协议 (每个信道独立 go module，按需引入)
│   ├── shadowsocks/ → extra/shadowsocks/go.mod (go-shadowsocks2)
│   ├── trojan/      → extra/trojan/go.mod      (零额外依赖)
│   ├── vmess/       → extra/vmess/go.mod       (sing-vmess)
│   ├── anytls/      → extra/anytls/go.mod      (sing-anytls)
│   ├── hysteria2/   → extra/hysteria2/go.mod   (hysteria core)
│   └── clash/       → extra/clash/go.mod       (yaml.v3, 订阅解析+健康检查)
│
├── loadbalance/ — 负载均衡策略
│   ├── round-robin, random, hash
│   ├── adaptive (基于延迟和成功率的自适应)
│   └── tracker (死节点检测)
│
├── socks/ — SOCKS4/5 协议实现 (含 UDP ASSOCIATE)
├── http/  — HTTP CONNECT 代理实现
└── example/ — 示例程序 (curl, nc, socks5)
```

## 核心概念

### Dial

所有协议的核心抽象是 `Dial` 类型：

```go
type Dial func(ctx context.Context, network, address string) (net.Conn, error)
```

与 `net.Dialer.DialContext` 和 `http.Transport.DialContext` 签名一致，可直接用于标准库。

### DialFactory

协议注册使用工厂函数：

```go
type DialFactory func(*url.URL, Dial) (Dial, error)
```

第一个参数是代理 URL（含配置信息），第二个参数是上游 Dial（用于代理链）。

### RegisterScheme

通过 `RegisterScheme` 注册协议：

```go
proxyclient.RegisterScheme("TROJAN", newTrojanProxyClient)
```

所有协议在各自包的 `init()` 中自动注册，用户只需 `import _` 即可启用。

### 代理链

`NewClientChain` 将多个代理 URL 串联，每一层的 `upstreamDial` 是上一层的输出：

```
Client → Dial(socks5) → Dial(http) → Target
```

## Module 边界

| Module | 路径 | 说明 |
|--------|------|------|
| `github.com/chainreactors/proxyclient` | `/` | 核心，最小依赖 |
| `github.com/chainreactors/proxyclient/extra/shadowsocks` | `/extra/shadowsocks` | Shadowsocks 客户端 |
| `github.com/chainreactors/proxyclient/extra/trojan` | `/extra/trojan` | Trojan 客户端 |
| `github.com/chainreactors/proxyclient/extra/vmess` | `/extra/vmess` | VMess + VLess 客户端 |
| `github.com/chainreactors/proxyclient/extra/anytls` | `/extra/anytls` | AnyTLS 客户端 |
| `github.com/chainreactors/proxyclient/extra/hysteria2` | `/extra/hysteria2` | Hysteria2 客户端 |
| `github.com/chainreactors/proxyclient/extra/clash` | `/extra/clash` | Clash 订阅 + 负载均衡 |

每个 extra module 独立 `go.mod`，只引入自身依赖，不会污染其他模块。
