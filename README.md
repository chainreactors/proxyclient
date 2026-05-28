# ProxyClient

一个功能强大的 Go 代理客户端库，支持多种代理协议，统一的 `Dial` 接口，可无缝集成到任何基于 `net.Conn` 的应用中。

本项目重构自 [github.com/RouterScript/ProxyClient](https://github.com/RouterScript/ProxyClient)。

Blog: https://chainreactors.github.io/wiki/blog/2025/02/14/proxyclient-introduce/

## 特性

- **统一接口** — 所有协议返回 `proxyclient.Dial`，与 `http.Transport.DialContext` 完全兼容
- **代理链** — `NewClientChain` 支持任意协议组合的多级代理链
- **插件式注册** — `RegisterScheme` + `init()` 自动注册，按需 `import _` 引入
- **独立 Module** — extra 中每个协议独立 go.mod，按需引入不污染依赖
- **负载均衡** — Round-Robin / Random / Hash / Adaptive + 死节点检测
- **Clash 订阅** — 解析订阅、GeoIP 过滤、健康检查、自动负载均衡
- **SOCKS5 UDP** — 完整 RFC 1928 UDP ASSOCIATE 支持

## 安装

```bash
go get github.com/chainreactors/proxyclient@latest
```

按需引入扩展协议：

```bash
go get github.com/chainreactors/proxyclient/extra/shadowsocks@latest
go get github.com/chainreactors/proxyclient/extra/trojan@latest
go get github.com/chainreactors/proxyclient/extra/vmess@latest
go get github.com/chainreactors/proxyclient/extra/anytls@latest
go get github.com/chainreactors/proxyclient/extra/hysteria2@latest
go get github.com/chainreactors/proxyclient/extra/clash@latest
```

## 快速开始

```go
proxy, _ := url.Parse("socks5://127.0.0.1:1080")
dial, _ := proxyclient.NewClient(proxy)

client := &http.Client{
    Transport: &http.Transport{DialContext: dial},
}
resp, _ := client.Get("https://example.com")
```

使用扩展协议：

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"
)

proxy, _ := url.Parse("trojan://password@server:443?sni=example.com")
dial, _ := proxyclient.NewClient(proxy)
```

使用 Webshell 代理（需 build tag：`go build -tags "suo5 neoreg"`）：

```go
import _ "github.com/chainreactors/proxyclient/webshell/suo5"

proxy, _ := url.Parse("suo5://target.com:8080/tunnel.jsp")
dial, _ := proxyclient.NewClient(proxy)
```

## 支持的协议

### 核心协议

| 协议 | Scheme |
|------|--------|
| Direct | `direct://` |
| Reject | `reject://` |
| Blackhole | `blackhole://` |
| HTTP/HTTPS | `http(s)://[user:pass@]host:port` |
| SOCKS4/4A | `socks4(a)://host:port` |
| SOCKS5 | `socks5://[user:pass@]host:port` (TCP + UDP) |
| SOCKS5+TLS | `socks5+tls://host:port` |
| SSH | `ssh://user:pass@host:port` (build tag: `proxyclient_ssh`) |

### 扩展协议 (extra/, 独立 go module)

| 协议 | Package | Scheme |
|------|---------|--------|
| Shadowsocks | `extra/shadowsocks` | `ss://method:password@host:port` |
| Trojan | `extra/trojan` | `trojan://password@host:port?sni=xxx` |
| VMess | `extra/vmess` | `vmess://host:port?id=uuid` |
| VLess | `extra/vmess` | `vless://uuid@host:port?security=tls` |
| AnyTLS | `extra/anytls` | `anytls://password@host:port` |
| Hysteria2 | `extra/hysteria2` | `hysteria2://password@host:port` |
| Clash 订阅 | `extra/clash` | `clash://?url=<subscribe-url>` |

### Webshell 隧道 (build tags)

| 协议 | Build Tag | Scheme |
|------|-----------|--------|
| Suo5 | `suo5` | `suo5(s)://host:port/path` |
| Neoreg | `neoreg` | `neoreg(s)://key@host:port/path` |

## 文档

- [快速开始](docs/quickstart.md) — 安装、用法、代码示例
- [架构](docs/architecture.md) — 项目结构、协议参考、负载均衡、Clash 订阅、Build Tags

## 参考

- [GameXG/ProxyClient](https://github.com/GameXG/ProxyClient)
- [RouterScript/ProxyClient](https://github.com/RouterScript/ProxyClient)
