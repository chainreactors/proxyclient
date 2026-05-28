# Clash 订阅集成

`extra/clash` 提供 Clash 订阅解析、节点管理、健康检查和负载均衡功能。

## 安装

```bash
go get github.com/chainreactors/proxyclient/extra/clash@latest
```

## 使用方式

### 方式一：URL Scheme

`clash` 包的 `init()` 自动注册 `clash://` scheme：

```go
import (
    "github.com/chainreactors/proxyclient"
    _ "github.com/chainreactors/proxyclient/extra/clash"
    // 注册需要的协议
    _ "github.com/chainreactors/proxyclient/extra/trojan"
    _ "github.com/chainreactors/proxyclient/extra/vmess"
)

proxy, _ := url.Parse("clash://?url=https%3A%2F%2Fexample.com%2Fsub&strategy=adaptive&country=HK,JP")
dial, _ := proxyclient.NewClient(proxy)
```

URL 参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `url` | (必需) Clash 订阅 URL，需 URL 编码 | — |
| `strategy` | 负载均衡策略 | `adaptive` |
| `country` | 按国家过滤（逗号分隔 ISO 3166-1 alpha-2） | — |
| `type` | 按协议类型过滤（trojan, vless, ss 等） | — |
| `name` | 按节点名称关键词过滤（不区分大小写） | — |
| `ua` | 拉取订阅时的 User-Agent | `clash` |
| `test` | 启用健康检查 (`true`/`1`) | — |
| `test-url` | 健康检查 URL | `https://www.google.com/generate_204` |

### 方式二：API

```go
import "github.com/chainreactors/proxyclient/extra/clash"

// 拉取订阅
sub, err := clash.FetchSubscription("https://example.com/subscribe")

// 过滤 + 创建 Dialer
dial, sub, err := clash.NewDialerFromSubscription(sub, clash.Options{
    Strategy: clash.StrategyAdaptive,
    Filter:   clash.FilterByCountry("HK", "JP"),
})

// 带健康检查
dial, sub, err := clash.NewDialerFromSubscription(sub, clash.Options{
    Strategy: clash.StrategyURLTest,
    HealthCheck: &clash.HealthCheckConfig{
        URL:         "https://www.google.com/generate_204",
        Timeout:     10 * time.Second,
        Concurrency: 20,
    },
})
```

## 负载均衡策略

| 策略 | 说明 |
|------|------|
| `adaptive` (默认) | 根据延迟、成功率、最近失败时间自适应排序 |
| `round-robin` | 轮询 |
| `random` | 随机 |
| `hash` | 一致性哈希（相同目标地址路由到同一节点） |
| `first` | 始终使用第一个节点 |
| `url-test` | 先健康检查，再使用 adaptive 策略 |

## 订阅格式

支持三种格式（自动检测）：

1. **Clash YAML** — 标准 Clash 配置文件格式
2. **Base64 + YAML** — Base64 编码后的 YAML
3. **URI-per-line** — 每行一个代理 URI（如 `trojan://...`, `ss://...`）

## 过滤器

```go
// 按国家
clash.FilterByCountry("HK", "JP", "US")

// 按协议类型
clash.FilterByType("trojan", "vless")

// 按名称关键词
clash.FilterByName("香港")

// 组合过滤（在 URL scheme 中自动组合）
```

GeoIP 使用内嵌的 IP 国家数据库，按服务器 IP 解析地理位置，无需外部服务。

## 健康检查

`HealthCheck` 并发测试所有可用节点，返回按延迟排序的结果：

```go
results := clash.HealthCheck(sub, &clash.HealthCheckConfig{
    URL:         "https://www.google.com/generate_204",
    Timeout:     10 * time.Second,
    Concurrency: 20,
}, nil)

for _, r := range results {
    if r.Err == nil {
        fmt.Printf("%s: %v\n", r.Node.Name, r.Latency)
    }
}

// 提取健康节点的 Dial
dials := clash.HealthyDials(results)
```
