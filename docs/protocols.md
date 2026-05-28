# 协议配置详解

## 核心协议

### Direct

```
格式: direct://[?timeout=5s]
```

直连，不经过任何代理。可选 `timeout` 参数设置连接超时。

### Reject

```
格式: reject://
```

拒绝所有连接，返回错误。

### Blackhole

```
格式: blackhole://
```

接受连接但丢弃所有数据。

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

### SOCKS4/4A

```
格式: socks4://host:port
      socks4a://host:port

SOCKS4A 支持域名解析，SOCKS4 仅支持 IPv4。仅支持 TCP。
```

### SOCKS5

支持 TCP CONNECT 和 UDP ASSOCIATE (RFC 1928)。

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

需要 build tag `proxyclient_ssh`。

```
格式: ssh://username[:password]@host:port[?public-key=/path/to/key]

示例:
  ssh://root:password@10.0.0.1:22
  ssh://root@10.0.0.1:22?public-key=/home/user/.ssh/id_rsa
```

## 扩展协议 (extra/)

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

## Webshell 隧道 (webshell/)

### Suo5

需要 build tag `suo5`。

```
格式: suo5://host:port/path
      suo5s://host:port/path  (HTTPS)

示例:
  suo5://target.com:8080/tunnel.jsp
  suo5s://target.com:8443/tunnel.jsp
```

### Neoreg

需要 build tag `neoreg`。

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
