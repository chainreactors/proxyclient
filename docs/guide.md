# ProxyClient 使用指南

## 架构概览

ProxyClient 的核心是一个 `Dial` 类型：

```go
type Dial func(ctx context.Context, network, address string) (net.Conn, error)
```

与 `http.Transport.DialContext` 签名一致，所有协议都返回这个类型，因此可以无缝用于标准库的 HTTP 客户端、gRPC、数据库连接等任何需要 `net.Conn` 的场景。

协议通过 `RegisterScheme` + `init()` 自注册。用户只需 `import _` 对应的包，即可在 `NewClient` 中使用该协议的 URL scheme。这种设计让使用者可以精确控制引入哪些协议及其依赖。

```
proxyclient
├── 核心协议 (零额外依赖)
│   direct, reject, blackhole, http(s), socks4/4a/5/5+tls
│
├── extra/ — 扩展协议，每个独立 go module
│   ├── ssh/          golang.org/x/crypto
│   ├── shadowsocks/  go-shadowsocks2
│   ├── trojan/       零额外依赖
│   ├── vmess/        sing-vmess (含 VLess)
│   ├── anytls/       sing-anytls
│   ├── hysteria2/    hysteria core (QUIC)
│   ├── suo5/         Suo5 Webshell 隧道
│   ├── neoreg/       Neoreg Webshell 隧道
│   ├── clash/        Clash 订阅解析 + 负载均衡
│   └── singtun/      TUN 透明代理入口
│
├── loadbalance/ — 负载均衡策略
└── example/ — 示例程序
```

每个 `extra/` 子包是独立的 Go module，拥有自己的 `go.mod`。引入 `extra/trojan` 不会拉入 hysteria2 的 QUIC 依赖，引入 `extra/ssh` 不会拉入 sing-vmess。这让最终二进制只包含实际使用的协议。

## 安装

核心库：

```bash
go get github.com/chainreactors/proxyclient@latest
```

按需引入扩展协议：

```bash
go get github.com/chainreactors/proxyclient/extra/ssh@latest
go get github.com/chainreactors/proxyclient/extra/shadowsocks@latest
go get github.com/chainreactors/proxyclient/extra/trojan@latest
go get github.com/chainreactors/proxyclient/extra/vmess@latest
go get github.com/chainreactors/proxyclient/extra/anytls@latest
go get github.com/chainreactors/proxyclient/extra/hysteria2@latest
go get github.com/chainreactors/proxyclient/extra/suo5@latest
go get github.com/chainreactors/proxyclient/extra/neoreg@latest
go get github.com/chainreactors/proxyclient/extra/clash@latest
go get github.com/chainreactors/proxyclient/extra/singtun@latest
```

## 基本用法

所有协议的使用方式相同：解析 URL → 创建 Dial → 使用。

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "net/url"

    "github.com/chainreactors/proxyclient"
)

func main() {
    proxy, _ := url.Parse("socks5://127.0.0.1:1080")
    dial, _ := proxyclient.NewClient(proxy)

    client := &http.Client{
        Transport: &http.Transport{DialContext: dial},
    }

    resp, _ := client.Get("https://example.com")
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

`Dial` 也可以直接使用，不限于 HTTP：

```go
conn, err := dial(ctx, "tcp", "example.com:443")
```

## 扩展协议

通过 `import _` 注册扩展协议，之后就可以在 URL 中使用对应的 scheme：

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/ssh"
    _ "github.com/chainreactors/proxyclient/extra/shadowsocks"
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"       // vmess:// + vless://
    _ "github.com/chainreactors/proxyclient/extra/anytls"
    _ "github.com/chainreactors/proxyclient/extra/hysteria2"   // hysteria2:// + hy2://
    _ "github.com/chainreactors/proxyclient/extra/suo5"        // suo5://, suo5s://
    _ "github.com/chainreactors/proxyclient/extra/neoreg"      // neoreg://, neoregs://
)

proxy, _ := url.Parse("trojan://password@server:443?sni=example.com")
dial, _ := proxyclient.NewClient(proxy)
```

## 代理链

将多个代理串联，流量依次经过每一跳：

```go
proxies := []*url.URL{
    parseURL("socks5://first-hop:1080"),
    parseURL("http://second-hop:8080"),
}
dial, err := proxyclient.NewClientChain(proxies)
// 效果：Client → SOCKS5 → HTTP → Target
```

## Webshell 代理

Suo5 和 Neoreg 是 Webshell 隧道协议，通过在目标服务器上部署的 JSP/PHP 等 Web 脚本建立代理通道。使用方式与其他扩展协议相同：

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/suo5"
    _ "github.com/chainreactors/proxyclient/extra/neoreg"
)

proxy, _ := url.Parse("suo5://target.com:8080/tunnel.jsp")
dial, _ := proxyclient.NewClient(proxy)
```

## Clash 订阅

`extra/clash` 可以解析 Clash 订阅（YAML / Base64 / URI-per-line），自动将节点转为负载均衡的 Dial。需要同时引入节点使用的协议包。

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"
    "github.com/chainreactors/proxyclient/extra/clash"
)

// API 方式
sub, _ := clash.FetchSubscription("https://example.com/subscribe")
dial, _, _ := clash.NewDialerFromSubscription(sub, clash.Options{
    Strategy: clash.StrategyAdaptive,
    Filter:   clash.FilterByCountry("HK", "JP"),
})

// 或通过 URL scheme（init() 自动注册 clash://）
proxy, _ := url.Parse("clash://?url=https%3A%2F%2Fexample.com%2Fsub&strategy=adaptive&country=HK,JP")
dial, _ := proxyclient.NewClient(proxy)
```

**负载均衡策略**：`adaptive`(默认) / `round-robin` / `random` / `hash` / `first` / `url-test`

**过滤器**：`FilterByCountry("HK","JP")` / `FilterByType("trojan","vless")` / `FilterByName("香港")`

内嵌 GeoIP 数据库，无需外部服务即可按国家过滤。`url-test` 策略会在首次使用前并发测试所有节点，自动选择最快的。

## 负载均衡

`loadbalance` 包可以将多个 Dial 合并为一个，适用于多节点场景：

```go
import "github.com/chainreactors/proxyclient/loadbalance"

dials := []proxyclient.Dial{dial1, dial2, dial3}

loadbalance.NewAdaptive(dials)   // 基于成功率+延迟+失败惩罚自适应
loadbalance.NewRoundRobin(dials) // 轮询
loadbalance.NewRandom(dials)     // 随机
loadbalance.NewHash(dials)       // 一致性哈希，相同目标地址 → 同一节点
```

所有策略内置死节点检测：连续 3 次失败标记为死亡，60s 冷却后重试，连接成功立即恢复。

## SOCKS5 UDP

SOCKS5 实现了完整的 RFC 1928 UDP ASSOCIATE。传入 `"udp"` network 时自动走 UDP 转发：

```go
dial, _ := proxyclient.NewClient(parseURL("socks5://127.0.0.1:1080"))
conn, _ := dial(ctx, "udp", "8.8.8.8:53")
conn.Write(dnsQuery)
conn.Read(dnsResponse)
```

## TUN 透明代理

`extra/singtun` 基于 `github.com/sagernet/sing-tun` 创建系统 TUN 设备，并把 TUN 中解析出的 TCP/UDP 会话转发到已有的 `proxyclient.Dial`。它是入口 runner，不注册 `tun://` scheme。

```go
import "github.com/chainreactors/proxyclient/extra/singtun"

dial, _ := proxyclient.NewClient(parseURL("socks5://127.0.0.1:1080"))
svc, err := singtun.Start(ctx, dial, singtun.Options{})
if err != nil {
    return err
}
defer svc.Close()
```

需要显式管理生命周期时，可以先构造、后启动：

```go
svc, err := singtun.New(ctx, dial, singtun.Options{})
if err != nil {
    return err
}
defer svc.Close()

if err := svc.Start(); err != nil {
    return err
}
running := svc.Running()
lastErr := svc.Err()
_ = running
_ = lastErr
```

`New` 只做校验和保存配置，不创建系统资源；`Start` 才创建 TUN runtime，启动失败会清理已创建资源；`Close` 幂等，未启动、已启动、启动失败后都可以安全调用。

默认 stack 是 `gvisor`，需要使用 `with_gvisor` build tag；创建 TUN 设备通常需要管理员/root 权限。默认不自动改系统路由，调用方可自行配置路由或显式启用 `Options.AutoRoute`。

## 协议参考

### 核心协议

| 协议 | 格式 |
|------|------|
| Direct | `direct://[?timeout=5s]` |
| Reject | `reject://` |
| Blackhole | `blackhole://` |
| HTTP/HTTPS | `http(s)://[user:pass@]host:port` |
| SOCKS4/4A | `socks4(a)://host:port` |
| SOCKS5 | `socks5://[user:pass@]host:port` (TCP + UDP) |
| SOCKS5+TLS | `socks5+tls://host:port` |

HTTP/HTTPS 额外参数：`tls-domain`, `tls-insecure-skip-verify`, `tls-ca-file`

### 扩展协议 (extra/)

| 协议 | 格式 | 关键参数 |
|------|------|----------|
| SSH | `ssh://user[:pass]@host:port` | `public-key` |
| Shadowsocks | `ss://method:password@host:port` | aes-256-gcm, chacha20-ietf-poly1305 等 |
| Trojan | `trojan://password@host:port` | `sni`, `allowInsecure` |
| VMess | `vmess://host:port?id=uuid` 或 base64(json) | `id`, `aid`, `security`, `tls`, `sni`, `net`, `path`, `host` |
| VLess | `vless://uuid@host:port` | `security`, `sni`, `flow`, `pbk`, `sid` |
| AnyTLS | `anytls://password@host:port` | `sni`, `insecure` |
| Hysteria2 | `hysteria2://password@host:port` | `sni`, `insecure` |
| Suo5 | `suo5(s)://host:port/path` | — |
| Neoreg | `neoreg(s)://key@host:port/path` | `timeout`, `retry`, `interval`, `buffer_size` |
| Clash | `clash://?url=<subscribe-url>` | `strategy`, `country`, `type`, `name`, `ua`, `test` |
| SingTUN | runner API | `name`, `mtu`, `stack`, `inet4`, `inet6`, `auto-route` |

## 示例程序

```bash
# curl — 通过代理访问 URL
go build ./example/curl
./curl -k --proxy socks5://127.0.0.1:1080 https://example.com

# nc — 通过代理连接主机端口
go build ./example/nc
./nc socks5://127.0.0.1:1080 example.com 80

# socks5 — 本地启动 SOCKS5 转发服务
go build ./example/socks5
./socks5 http://127.0.0.1:8080 :1080
```
