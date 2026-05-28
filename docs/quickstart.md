# 快速开始

## 安装

```bash
go get github.com/chainreactors/proxyclient@latest
```

按需引入扩展协议（每个独立 module）：

```bash
go get github.com/chainreactors/proxyclient/extra/shadowsocks@latest
go get github.com/chainreactors/proxyclient/extra/trojan@latest
go get github.com/chainreactors/proxyclient/extra/vmess@latest
go get github.com/chainreactors/proxyclient/extra/anytls@latest
go get github.com/chainreactors/proxyclient/extra/hysteria2@latest
go get github.com/chainreactors/proxyclient/extra/clash@latest
```

## 基本用法

```go
proxy, _ := url.Parse("socks5://127.0.0.1:1080")
dial, _ := proxyclient.NewClient(proxy)

client := &http.Client{
    Transport: &http.Transport{DialContext: dial},
}
resp, _ := client.Get("https://example.com")
```

## 代理链

```go
proxies := []*url.URL{
    parseURL("socks5://first-hop:1080"),
    parseURL("http://second-hop:8080"),
}
dial, _ := proxyclient.NewClientChain(proxies)
```

## 扩展协议

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"
)

proxy, _ := url.Parse("trojan://password@server:443?sni=example.com")
dial, _ := proxyclient.NewClient(proxy)
```

## Webshell 代理

编译：`go build -tags "suo5 neoreg"`

```go
import _ "github.com/chainreactors/proxyclient/webshell/suo5"

proxy, _ := url.Parse("suo5://target.com:8080/tunnel.jsp")
dial, _ := proxyclient.NewClient(proxy)
```

## Clash 订阅

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"
    "github.com/chainreactors/proxyclient/extra/clash"
)

sub, _ := clash.FetchSubscription("https://example.com/subscribe")
dial, _, _ := clash.NewDialerFromSubscription(sub, clash.Options{
    Strategy: clash.StrategyAdaptive,
    Filter:   clash.FilterByCountry("HK", "JP"),
})
```

## 负载均衡

```go
import "github.com/chainreactors/proxyclient/loadbalance"

dials := []proxyclient.Dial{dial1, dial2, dial3}
dial := loadbalance.NewAdaptive(dials)   // 自适应
dial := loadbalance.NewRoundRobin(dials) // 轮询
dial := loadbalance.NewRandom(dials)     // 随机
dial := loadbalance.NewHash(dials)       // 一致性哈希
```

## SOCKS5 UDP

```go
dial, _ := proxyclient.NewClient(parseURL("socks5://127.0.0.1:1080"))
conn, _ := dial(ctx, "udp", "8.8.8.8:53")
conn.Write(dnsQuery)
conn.Read(dnsResponse)
```

## 示例程序

```bash
# curl — 通过代理访问 URL
go build ./example/curl
./curl -k --proxy socks5://127.0.0.1:1080 https://example.com

# nc — 通过代理连接主机端口
go build ./example/nc
./nc socks5://127.0.0.1:1080 example.com 80

# socks5 — 本地 SOCKS5 转发服务
go build ./example/socks5
./socks5 http://127.0.0.1:8080 :1080
```
