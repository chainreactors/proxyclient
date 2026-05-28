# 架构

## 项目结构

```
proxyclient (核心)
├── 内置协议: direct, reject, blackhole, http(s), socks4/4a/5/5+tls
├── 可选协议 (build tag):
│   └── proxyclient_ssh → SSH
│
├── webshell/ — Webshell 隧道代理 (build tag 控制)
│   ├── suo5/    (suo5)
│   └── neoreg/  (neoreg)
│
├── extra/ — 扩展协议 (每个信道独立 go module)
│   ├── shadowsocks/  (go-shadowsocks2)
│   ├── trojan/       (零额外依赖)
│   ├── vmess/        (sing-vmess, 含 VLess)
│   ├── anytls/       (sing-anytls)
│   ├── hysteria2/    (hysteria core)
│   └── clash/        (yaml.v3, 订阅+健康检查+负载均衡)
│
├── loadbalance/ — round-robin, random, hash, adaptive + 死节点检测
├── socks/ — SOCKS4/5 实现 (含 UDP ASSOCIATE)
├── http/  — HTTP CONNECT 实现
└── example/ — curl, nc, socks5
```

## 核心概念

### Dial

```go
type Dial func(ctx context.Context, network, address string) (net.Conn, error)
```

所有协议返回 `Dial`，与 `http.Transport.DialContext` 签名一致。

### 协议注册

```go
type DialFactory func(*url.URL, Dial) (Dial, error)

proxyclient.RegisterScheme("TROJAN", newTrojanProxyClient)
```

所有协议在 `init()` 中自注册，`import _` 即可启用。

### 代理链

```go
dial, _ := proxyclient.NewClientChain(proxies)
// Client → Dial(socks5) → Dial(http) → Target
```

每一层的 `upstreamDial` 是上一层的输出。

## 协议参考

### 核心协议

| 协议 | 格式 | 说明 |
|------|------|------|
| Direct | `direct://[?timeout=5s]` | 直连 |
| Reject | `reject://` | 拒绝连接 |
| Blackhole | `blackhole://` | 接受但丢弃数据 |
| HTTP/HTTPS | `http(s)://[user:pass@]host:port` | 支持 `tls-domain`, `tls-insecure-skip-verify`, `tls-ca-file` 参数 |
| SOCKS4/4A | `socks4(a)://host:port` | 4A 支持域名，仅 TCP |
| SOCKS5 | `socks5://[user:pass@]host:port` | TCP + UDP ASSOCIATE (RFC 1928) |
| SOCKS5+TLS | `socks5+tls://host:port` | |
| SSH | `ssh://user[:pass]@host:port[?public-key=path]` | build tag: `proxyclient_ssh` |

### 扩展协议 (extra/)

每个独立 go module，`import _` 引入，无需 build tag。

| 协议 | 格式 | 关键参数 |
|------|------|----------|
| Shadowsocks | `ss://method:password@host:port` | 支持 aes-256-gcm, chacha20-ietf-poly1305 等 |
| Trojan | `trojan://password@host:port` | `sni`, `allowInsecure` |
| VMess | `vmess://host:port?id=uuid` 或 `vmess://base64(json)` | `id`, `aid`, `security`, `tls`, `sni`, `net`, `path`, `host` |
| VLess | `vless://uuid@host:port` | `security` (tls/reality/none), `sni`, `flow`, `pbk`, `sid` |
| AnyTLS | `anytls://password@host:port` | `sni`, `insecure` |
| Hysteria2 | `hysteria2://password@host:port` (别名 `hy2://`) | `sni`, `insecure`, `auth` |
| Clash | `clash://?url=<subscribe-url>` | `strategy`, `country`, `type`, `name`, `ua`, `test`, `test-url` |

### Webshell 隧道 (webshell/)

需要 build tag。

| 协议 | 格式 | Build Tag | 参数 |
|------|------|-----------|------|
| Suo5 | `suo5(s)://host:port/path` | `suo5` | — |
| Neoreg | `neoreg(s)://key@host:port/path` | `neoreg` | `timeout`, `retry`, `interval`, `buffer_size` |

## 负载均衡

```go
import "github.com/chainreactors/proxyclient/loadbalance"

loadbalance.NewRoundRobin(dials)  // 轮询
loadbalance.NewRandom(dials)      // 随机
loadbalance.NewHash(dials)        // 一致性哈希 (相同目标 → 同一节点)
loadbalance.NewAdaptive(dials)    // 自适应 (成功率+延迟+失败惩罚)
```

**Adaptive** 基于成功率、平均延迟、最近失败时间综合评分，每 10 次调用重排序。

**死节点检测 (Tracker)**：连续 3 次失败标记死亡，60s 后允许重试，所有节点死亡时回退全部重试。Round-Robin/Random/Hash 均内置 Tracker。

## Clash 订阅

```go
import "github.com/chainreactors/proxyclient/extra/clash"

// URL scheme 方式
proxy, _ := url.Parse("clash://?url=https%3A%2F%2Fexample.com%2Fsub&strategy=adaptive&country=HK,JP")

// API 方式
sub, _ := clash.FetchSubscription("https://example.com/subscribe")
dial, _, _ := clash.NewDialerFromSubscription(sub, clash.Options{
    Strategy:    clash.StrategyAdaptive,
    Filter:      clash.FilterByCountry("HK", "JP"),
    HealthCheck: &clash.HealthCheckConfig{},  // 可选：启用健康检查
})
```

支持 Clash YAML / Base64+YAML / URI-per-line 三种订阅格式，自动检测。
内嵌 GeoIP 数据库，支持 `FilterByCountry`、`FilterByType`、`FilterByName`。
策略：`adaptive`(默认) / `round-robin` / `random` / `hash` / `first` / `url-test`。

## Build Tags

| Tag | 协议 |
|-----|------|
| `proxyclient_ssh` | SSH |
| `suo5` | Suo5 |
| `neoreg` | Neoreg |

```bash
go build -tags "proxyclient_ssh suo5 neoreg"
```

extra 协议不需要 build tag，通过 `import _` 引入，按需 `go get` 单个协议。
