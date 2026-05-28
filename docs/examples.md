# 示例

## 示例程序

### Curl

模拟 curl 命令，通过代理访问指定 URL。

```bash
go build ./example/curl
./curl -k --proxy socks5://127.0.0.1:1080 https://example.com
```

### NC

模拟 nc 命令，通过代理连接指定主机和端口。

```bash
go build ./example/nc
./nc socks5://127.0.0.1:1080 example.com 80
```

### SOCKS5 转发

在本地启动 SOCKS5 服务器，将所有流量通过上游代理转发。

```bash
go build ./example/socks5
./socks5 http://127.0.0.1:8080 :1080
```

## 代码示例

### 基本代理

```go
proxy, _ := url.Parse("socks5://127.0.0.1:1080")
dial, _ := proxyclient.NewClient(proxy)

client := &http.Client{
    Transport: &http.Transport{DialContext: dial},
}
resp, _ := client.Get("https://example.com")
```

### 代理链

```go
proxies := []*url.URL{
    parseURL("socks5://first-hop:1080"),
    parseURL("http://second-hop:8080"),
}
dial, _ := proxyclient.NewClientChain(proxies)
```

### 扩展协议

```go
import (
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"
)

proxy, _ := url.Parse("trojan://password@server:443?sni=example.com")
dial, _ := proxyclient.NewClient(proxy)
```

### Webshell 代理

编译时需要 build tag：`go build -tags "suo5 neoreg"`

```go
import (
    _ "github.com/chainreactors/proxyclient/webshell/suo5"
    _ "github.com/chainreactors/proxyclient/webshell/neoreg"
)

proxy, _ := url.Parse("suo5://target.com:8080/tunnel.jsp")
dial, _ := proxyclient.NewClient(proxy)
```

### Clash 订阅 + 负载均衡

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

### SOCKS5 UDP

```go
dial, _ := proxyclient.NewClient(parseURL("socks5://127.0.0.1:1080"))
conn, _ := dial(ctx, "udp", "8.8.8.8:53")
conn.Write(dnsQuery)
conn.Read(dnsResponse)
```

### 负载均衡

```go
import "github.com/chainreactors/proxyclient/loadbalance"

dials := []proxyclient.Dial{dial1, dial2, dial3}
dial := loadbalance.NewAdaptive(dials)
```
