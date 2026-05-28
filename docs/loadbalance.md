# 负载均衡

`loadbalance` 包提供多种负载均衡策略，将多个 `proxyclient.Dial` 合并为一个。

## 策略

### Round-Robin

```go
dial := loadbalance.NewRoundRobin(dials)
```

按顺序轮流选择节点。

### Random

```go
dial := loadbalance.NewRandom(dials)
```

每次随机选择一个节点。

### Hash

```go
dial := loadbalance.NewHash(dials)
```

根据目标地址的 CRC32 哈希选择节点。相同目标地址始终路由到同一节点。

### Adaptive

```go
dial := loadbalance.NewAdaptive(dials)
```

基于多维度指标自适应选择最优节点：

- **成功率** — 历史连接成功/失败比
- **延迟** — 平均连接延迟（sigmoid 归一化，1000ms → 0.5 分）
- **最近失败惩罚** — 最近失败的节点权重指数衰减（60s 半衰期）

每 10 次调用重新排序，优先尝试得分最高的节点，失败后自动回退到下一个。

## 死节点检测 (Tracker)

Round-Robin、Random、Hash 策略内置 `Tracker`：

- 连续失败 **3 次** → 标记为死亡
- 死亡后 **60 秒** 冷却期 → 允许重试
- 所有节点死亡 → 回退到全部节点重试
- 连接成功 → 立即恢复

每次 `Dial` 失败时，自动尝试其他存活节点作为 fallback。
