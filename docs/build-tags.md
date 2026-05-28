# Build Tags

为减小二进制体积，部分协议需要通过 build tag 启用。

## 可用 Build Tags

| Tag | 协议 | 包路径 |
|-----|------|--------|
| `proxyclient_ssh` | SSH | `proxyclient` (内置) |
| `suo5` | Suo5 webshell 隧道 | `webshell/suo5` |
| `neoreg` | Neoreg webshell 隧道 | `webshell/neoreg` |

## 编译示例

```bash
# 仅启用 SSH
go build -tags proxyclient_ssh

# 启用 Webshell 代理
go build -tags "suo5 neoreg"

# 全部 build tag 启用
go build -tags "proxyclient_ssh suo5 neoreg"
```

默认编译不包含这些协议。未启用时对应 scheme 不会注册，`NewClient` 返回 `unsupported proxy client.`。

## extra 协议

`extra/` 中的协议（Shadowsocks、Trojan、VMess、VLess、AnyTLS、Hysteria2、Clash）**不需要** build tag。它们是独立 Go module，通过 `import _` 引入：

```go
import _ "github.com/chainreactors/proxyclient/extra/trojan"
```

按需 `go get` 单个协议不会引入其他协议的依赖：

```bash
go get github.com/chainreactors/proxyclient/extra/trojan@latest
```
