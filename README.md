# ProxyClient

一个功能强大的 Go 代理客户端库，支持多种代理协议，统一的 `Dial` 接口，可无缝集成到任何基于 `net.Conn` 的应用中。

本项目重构自 [github.com/RouterScript/ProxyClient](https://github.com/RouterScript/ProxyClient)。

Blog: https://chainreactors.github.io/wiki/blog/2025/02/14/proxyclient-introduce/

## 特性

- **统一接口** — 所有协议返回 `proxyclient.Dial`，与 `http.Transport.DialContext` 完全兼容
- **代理链** — `NewClientChain` 支持任意协议组合的多级代理链
- **插件式注册** — `RegisterScheme` + `init()` 自动注册，`import _` 按需引入
- **独立 Module** — extra/ 每个协议独立 go.mod，按需引入不污染依赖
- **负载均衡** — Round-Robin / Random / Hash / Adaptive + 死节点检测
- **Clash 订阅** — 解析订阅、GeoIP 过滤、健康检查、自动负载均衡
- **SOCKS5 UDP** — 完整 RFC 1928 UDP ASSOCIATE 支持

## 快速开始

```go
proxy, _ := url.Parse("socks5://127.0.0.1:1080")
dial, _ := proxyclient.NewClient(proxy)

client := &http.Client{
    Transport: &http.Transport{DialContext: dial},
}
resp, _ := client.Get("https://example.com")
```

使用扩展协议只需 `import _` 对应的包：

```go
import _ "github.com/chainreactors/proxyclient/extra/trojan"

proxy, _ := url.Parse("trojan://password@server:443?sni=example.com")
dial, _ := proxyclient.NewClient(proxy)
```

## 支持的协议

### 核心协议

| 协议 | Scheme |
|------|--------|
| Direct / Reject / Blackhole | `direct://`, `reject://`, `blackhole://` |
| HTTP/HTTPS | `http(s)://[user:pass@]host:port` |
| SOCKS4/4A/5 | `socks4(a)://`, `socks5://[user:pass@]host:port` (TCP+UDP) |
| SOCKS5+TLS | `socks5+tls://host:port` |

### 扩展协议 (extra/, 独立 go module)

| 协议 | Package | Scheme |
|------|---------|--------|
| SSH | `extra/ssh` | `ssh://user:pass@host:port` |
| Shadowsocks | `extra/shadowsocks` | `ss://method:password@host:port` |
| Trojan | `extra/trojan` | `trojan://password@host:port` |
| VMess | `extra/vmess` | `vmess://host:port?id=uuid` |
| VLess | `extra/vmess` | `vless://uuid@host:port` |
| AnyTLS | `extra/anytls` | `anytls://password@host:port` |
| Hysteria2 | `extra/hysteria2` | `hysteria2://password@host:port` |
| Suo5 | `extra/suo5` | `suo5(s)://host:port/path` |
| Neoreg | `extra/neoreg` | `neoreg(s)://key@host:port/path` |
| Clash 订阅 | `extra/clash` | `clash://?url=<subscribe-url>` |
| TUN 透明代理 | `extra/singtun` | runner API, 使用 `proxyclient.Dial` 作为出站 |

## 文档

详细使用指南、架构说明、协议参考见 **[docs/guide.md](docs/guide.md)**。

## 参考

- [GameXG/ProxyClient](https://github.com/GameXG/ProxyClient)
- [RouterScript/ProxyClient](https://github.com/RouterScript/ProxyClient)
