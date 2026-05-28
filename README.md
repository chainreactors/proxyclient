# ProxyClient

一个功能强大的 Go 代理客户端库，支持多种代理协议，统一的 `Dial` 接口，可无缝集成到任何基于 `net.Conn` 的应用中。

本项目重构自 [github.com/RouterScript/ProxyClient](https://github.com/RouterScript/ProxyClient)。

Blog: https://chainreactors.github.io/wiki/blog/2025/02/14/proxyclient-introduce/

## 特性

- **统一接口** — 所有协议返回 `proxyclient.Dial`（即 `func(ctx, network, address) (net.Conn, error)`），与 `http.Transport.DialContext` 完全兼容
- **代理链** — `NewClientChain` 支持任意协议组合的多级代理链
- **插件式协议注册** — 通过 `RegisterScheme` + `init()` 自动注册，按需引入
- **Build Tags 控制体积** — SSH、Shadowsocks、Suo5、Neoreg 均可通过 build tag 选择性编译
- **负载均衡** — 内置 Round-Robin、Random、Hash、Adaptive 四种策略，支持死节点检测与自动恢复
- **Clash 订阅集成** — 解析 Clash YAML/Base64/URI 订阅，自动创建负载均衡 Dialer
- **SOCKS5 UDP ASSOCIATE** — 完整支持 RFC 1928 UDP 转发
- **GeoIP 过滤** — 内嵌 IP 国家数据库，按地区筛选节点

## 架构

```
proxyclient (核心)
├── 内置协议: direct, reject, blackhole, http(s), socks4/4a/5/5+tls
├── 可选协议 (build tags):
│   ├── proxyclient_ssh        → SSH
│   └── proxyclient_shadowsocks → Shadowsocks
│
├── webshell/ — Webshell 隧道代理
│   ├── suo5/    (build tag: suo5)
│   └── neoreg/  (build tag: neoreg)
│
├── extra/ — 独立第三方信道 (独立 go module)
│   ├── trojan/
│   ├── vmess/ (VMess + VLess)
│   ├── anytls/
│   ├── hysteria2/
│   └── clash/ — Clash 订阅解析 + 节点管理 + 健康检查
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

## 安装

```bash
go get github.com/chainreactors/proxyclient@latest
```

引入第三方协议（extra 是独立 module）:

```bash
go get github.com/chainreactors/proxyclient/extra@latest
```

## 快速开始

### 基本用法

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
		Transport: &http.Transport{
			DialContext: dial,
		},
	}

	resp, err := client.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

### 代理链

```go
proxies := []*url.URL{
	parseURL("socks5://first-hop:1080"),
	parseURL("http://second-hop:8080"),
}
dial, err := proxyclient.NewClientChain(proxies)
```

### 使用第三方协议 (extra)

```go
import (
	"github.com/chainreactors/proxyclient"
	_ "github.com/chainreactors/proxyclient/extra/trojan"   // 注册 trojan://
	_ "github.com/chainreactors/proxyclient/extra/vmess"    // 注册 vmess://, vless://
	_ "github.com/chainreactors/proxyclient/extra/anytls"   // 注册 anytls://
	_ "github.com/chainreactors/proxyclient/extra/hysteria2" // 注册 hysteria2://, hy2://
)

proxy, _ := url.Parse("trojan://password@server:443?sni=example.com")
dial, _ := proxyclient.NewClient(proxy)
```

### 使用 Webshell 代理

需要 build tag 启用：

```bash
go build -tags "suo5 neoreg" .
```

```go
import (
	_ "github.com/chainreactors/proxyclient/webshell" // 注册 suo5://, neoreg://
)

proxy, _ := url.Parse("suo5://target.com:8080/tunnel.jsp")
dial, _ := proxyclient.NewClient(proxy)
```

### Clash 订阅

```go
import (
	_ "github.com/chainreactors/proxyclient/extra/trojan"
	_ "github.com/chainreactors/proxyclient/extra/vmess"
	_ "github.com/chainreactors/proxyclient/extra/hysteria2"
	"github.com/chainreactors/proxyclient/extra/clash"
)

// 方式一：通过 URL scheme（自动注册 clash://）
import _ "github.com/chainreactors/proxyclient/extra/clash"

proxy, _ := url.Parse("clash://?url=https%3A%2F%2Fexample.com%2Fsub&strategy=adaptive&country=HK,JP")
dial, _ := proxyclient.NewClient(proxy)

// 方式二：直接 API
sub, _ := clash.FetchSubscription("https://example.com/subscribe")
dial, _, _ := clash.NewDialerFromSubscription(sub, clash.Options{
	Strategy: clash.StrategyAdaptive,
	Filter:   clash.FilterByCountry("HK", "JP"),
})
```

### 负载均衡

```go
import "github.com/chainreactors/proxyclient/loadbalance"

dials := []proxyclient.Dial{dial1, dial2, dial3}

// 自适应（根据延迟+成功率自动排序）
dial := loadbalance.NewAdaptive(dials)

// 轮询
dial := loadbalance.NewRoundRobin(dials)

// 随机
dial := loadbalance.NewRandom(dials)

// 一致性哈希（相同目标地址路由到同一节点）
dial := loadbalance.NewHash(dials)
```

## 支持的协议

### 核心协议（无额外依赖）

| 协议 | Scheme | 说明 |
|------|--------|------|
| Direct | `direct://` | 直连 |
| Reject | `reject://` | 拒绝连接 |
| Blackhole | `blackhole://` | 黑洞（接受连接但丢弃数据）|
| HTTP | `http://host:port` | HTTP CONNECT 代理 |
| HTTPS | `https://host:port` | HTTPS CONNECT 代理 |
| SOCKS4 | `socks4://host:port` | SOCKS4 代理 |
| SOCKS4A | `socks4a://host:port` | SOCKS4A 代理（支持域名）|
| SOCKS5 | `socks5://[user:pass@]host:port` | SOCKS5 代理（TCP + UDP）|
| SOCKS5+TLS | `socks5+tls://host:port` | SOCKS5 over TLS |

### 可选协议（Build Tags）

| 协议 | Build Tag | Scheme |
|------|-----------|--------|
| SSH | `proxyclient_ssh` | `ssh://user:pass@host:port` |
| Shadowsocks | `proxyclient_shadowsocks` | `ss://method:password@host:port` |

### Webshell 隧道（Build Tags）

| 协议 | Build Tag | Scheme |
|------|-----------|--------|
| Suo5 | `suo5` | `suo5://host:port/path`, `suo5s://` |
| Neoreg | `neoreg` | `neoreg://key@host:port/path`, `neoregs://` |

### 第三方信道（extra module）

| 协议 | Package | Scheme |
|------|---------|--------|
| Trojan | `extra/trojan` | `trojan://password@host:port?sni=xxx` |
| VMess | `extra/vmess` | `vmess://host:port?id=uuid&security=auto` |
| VLess | `extra/vmess` | `vless://uuid@host:port?security=tls&sni=xxx` |
| AnyTLS | `extra/anytls` | `anytls://password@host:port?sni=xxx` |
| Hysteria2 | `extra/hysteria2` | `hysteria2://password@host:port?sni=xxx`, `hy2://` |
| Clash 订阅 | `extra/clash` | `clash://?url=<subscribe-url>&strategy=adaptive` |

## 协议配置详解

### HTTP/HTTPS

```
格式: http(s)://[username:password@]host:port
参数:
  - tls-domain: TLS SNI 域名
  - tls-insecure-skip-verify: 跳过证书验证 (true/false)
  - tls-ca-file: 自定义 CA 证书路径

示例:
  http://user:pass@127.0.0.1:8080
  https://127.0.0.1:8443?tls-insecure-skip-verify=true
```

### SOCKS5

支持 TCP CONNECT 和 UDP ASSOCIATE。

```
格式: socks5://[username:password@]host:port
      socks5+tls://host:port

示例:
  socks5://127.0.0.1:1080
  socks5://user:pass@127.0.0.1:1080
```

UDP 用法：

```go
dial, _ := proxyclient.NewClient(parseURL("socks5://127.0.0.1:1080"))
conn, _ := dial(ctx, "udp", "8.8.8.8:53")  // 自动使用 UDP ASSOCIATE
conn.Write(dnsQuery)
conn.Read(dnsResponse)
```

### SSH

```
格式: ssh://username[:password]@host:port[?public-key=/path/to/key]

示例:
  ssh://root:password@10.0.0.1:22
  ssh://root@10.0.0.1:22?public-key=/home/user/.ssh/id_rsa
```

### Shadowsocks

```
格式: ss://method:password@host:port

支持的加密方式: aes-256-gcm, chacha20-ietf-poly1305 等
示例:
  ss://aes-256-gcm:password@127.0.0.1:8388
```

### Trojan

```
格式: trojan://password@host:port[?sni=xxx&allowInsecure=true]

参数:
  - sni: TLS SNI（默认使用 host）
  - allowInsecure: 跳过证书验证

示例:
  trojan://mypassword@server.com:443?sni=example.com
```

### VMess

```
格式: vmess://host:port?id=uuid[&security=auto&tls=true&sni=xxx]
      vmess://base64(json)  (标准分享格式)

参数:
  - id: UUID
  - aid: AlterID (默认 0)
  - security: 加密方式 (auto, aes-128-gcm, chacha20-poly1305)
  - tls: 启用 TLS (true/false)
  - sni: TLS SNI
  - net: 传输方式 (tcp, ws)
  - path: WebSocket 路径
  - host: WebSocket Host
```

### VLess

```
格式: vless://uuid@host:port[?security=tls&sni=xxx&flow=xxx]

参数:
  - security: tls, reality, none
  - sni: TLS SNI
  - flow: 流控 (xtls-rprx-vision)
  - allowInsecure: 跳过证书验证
  - pbk: Reality public key
  - sid: Reality short ID
```

### AnyTLS

```
格式: anytls://password@host:port[?sni=xxx&insecure=true]
```

### Hysteria2

```
格式: hysteria2://password@host:port[?sni=xxx&insecure=true]
      hy2://password@host:port

参数:
  - sni: TLS SNI（默认使用 host）
  - insecure: 跳过证书验证
  - auth: 认证密码（也可放在 userinfo 中）
```

### Suo5

```
格式: suo5://host:port/path
      suo5s://host:port/path  (HTTPS)

示例:
  suo5://target.com:8080/tunnel.jsp
  suo5s://target.com:8443/tunnel.jsp
```

### Neoreg

```
格式: neoreg://key@host:port/path[?timeout=5s&retry=10&interval=100ms]
      neoregs://key@host:port/path  (HTTPS)

参数:
  - key: 连接密钥（必需，放在 userinfo 中）
  - timeout: 连接超时（默认 5s）
  - retry: 最大重试次数（默认 10）
  - interval: 读写间隔（默认 100ms）
  - buffer_size: 读取缓冲区大小（默认 32KB）
```

### Clash 订阅

```
格式: clash://?url=<encoded-subscribe-url>[&strategy=adaptive][&country=HK,JP][&type=trojan,vless]

参数:
  - url: (必需) Clash 订阅 URL，需 URL 编码
  - strategy: 负载均衡策略
    - adaptive (默认): 根据延迟和成功率自适应
    - round-robin: 轮询
    - random: 随机
    - hash: 一致性哈希
    - first: 始终使用第一个节点
    - url-test: 先健康检查，再自适应
  - country: 按国家过滤（逗号分隔的 ISO 3166-1 alpha-2 代码）
  - type: 按协议类型过滤（trojan, vless, ss 等）
  - name: 按节点名称关键词过滤
  - ua: 拉取订阅时的 User-Agent（默认 "clash"）
  - test: 启用健康检查 (true/1)
  - test-url: 健康检查 URL（默认 google generate_204）
```

## Build Tags

为减小二进制体积，部分协议需要通过 build tag 启用：

```bash
# 启用 SSH
go build -tags proxyclient_ssh

# 启用 Shadowsocks
go build -tags proxyclient_shadowsocks

# 启用 Webshell 代理
go build -tags "suo5 neoreg"

# 全部启用
go build -tags "proxyclient_ssh proxyclient_shadowsocks suo5 neoreg"
```

默认编译不包含这些协议。未启用时，对应的 scheme 不会注册，`NewClient` 返回 `unsupported proxy client.`。

extra 模块中的协议（trojan, vmess, anytls, hysteria2, clash）通过 `import _` 引入，无需 build tag。

## 示例程序

### Curl

```bash
go build ./example/curl
./curl -k --proxy socks5://127.0.0.1:1080 https://example.com
```

### NC

```bash
go build ./example/nc
./nc socks5://127.0.0.1:1080 example.com 80
```

### SOCKS5 转发

```bash
go build ./example/socks5
./socks5 http://127.0.0.1:8080 :1080
# 在本地 :1080 启动 SOCKS5 服务，流量通过上游 HTTP 代理转发
```

## 参考

- [GameXG/ProxyClient](https://github.com/GameXG/ProxyClient)
- [RouterScript/ProxyClient](https://github.com/RouterScript/ProxyClient)
