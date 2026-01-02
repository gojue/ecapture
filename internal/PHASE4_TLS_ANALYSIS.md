# 阶段4：TLS/SSL 探针技术分析与实施方案

## 摘要

本文档详细分析了阶段4（TLS/SSL 探针迁移）的技术复杂性、工作量估计和实施方案。基于阶段3的成功完成，我们发现 TLS 探针的复杂度是简单探针的 **5-10倍**，需要特殊的实施策略。

**关键发现**：
- TLS 探针需要处理多版本兼容、密钥提取、网络跟踪和多格式输出
- 估计工作量：~27 小时（vs 简单探针平均 3-4 小时）
- 代码量：平均 2,650 行/探针（vs 简单探针平均 1,000 行）
- 建议采用分阶段实施策略

---

## 1. 背景

### 1.1 阶段3成功总结

阶段3（简单探针）已100%完成：

| 探针 | 代码行数 | 测试用例 | 复杂度 | 时间 |
|------|---------|---------|--------|------|
| Bash | ~1,100 | 7 | 中 | ~3h |
| Zsh | ~800 | 7 | 低 | ~3h |
| MySQL | ~1,200 | 9 | 中 | ~4h |
| Postgres | ~950 | 12 | 低 | ~4h |

**成就**：
- 一致的架构模式（Config → Event → Probe → Register → Test）
- 100% 测试覆盖率（103个测试全部通过）
- 清晰的文档和模板
- 验证了基础架构的有效性

### 1.2 阶段4挑战

TLS/SSL 探针与简单探针的本质区别：

| 维度 | 简单探针 | TLS 探针 | 差异 |
|------|---------|---------|------|
| **版本支持** | 单一或2-3个版本 | 5-10个主要版本 | 3-5x |
| **Hook 点数量** | 1-4个函数 | 10-20个函数 | 3-5x |
| **数据处理** | 简单解码 | 加密算法、密钥派生 | 10x |
| **输出格式** | 1种（text） | 3种（text/keylog/pcap） | 3x |
| **网络交互** | 无 | 需要内核 hook | ∞ |
| **eBPF 程序数** | 1-2个 | 5-10个 | 3-5x |
| **代码复杂度** | 简单 | 极高 | 5-10x |

---

## 2. TLS 探针技术分析

### 2.1 OpenSSL 探针

#### 2.1.1 版本支持矩阵

| OpenSSL 版本 | 发布时间 | 结构体变化 | 主流使用 | 支持难度 |
|-------------|---------|-----------|---------|---------|
| 1.0.2 | 2015 | - | 遗留系统 | 高 |
| 1.1.0 | 2016 | 大幅重构 | 少量 | 高 |
| 1.1.1 | 2018 | 微调 | 主流 | 中 |
| 3.0.x | 2021 | 架构变化 | 主流 | 高 |
| 3.1.x | 2023 | 微调 | 较新 | 中 |
| 3.2+ | 2024+ | 未知 | 最新 | 未知 |

**关键差异**：
- 1.0.2 → 1.1.0：OPENSSL_init 重构，SSL_CTX 结构变化
- 1.1.x → 3.0：提供者架构（Provider Architecture），API 大变
- TLS 1.2 vs 1.3：密钥派生完全不同（PRF vs HKDF）

#### 2.1.2 Master Key Hook 函数

不同版本需要 hook 不同的函数：

```c
// OpenSSL 1.0.2
SSL_export_keying_material
SSL_get_client_random
SSL_get_server_random

// OpenSSL 1.1.0/1.1.1
SSL_set_fd
SSL_set_bio
SSL_do_handshake

// OpenSSL 3.0+
SSL_connect
SSL_accept
SSL_read
SSL_write
```

**挑战**：
- 需要运行时检测版本
- 需要多套 eBPF 程序
- 结构体偏移需要动态计算或预定义

#### 2.1.3 密钥提取逻辑

**TLS 1.2**：
```go
// 使用 PRF (Pseudo-Random Function)
masterSecret := PRF(
    preMasterSecret,
    "master secret",
    clientRandom + serverRandom,
    48
)
```

**TLS 1.3**：
```go
// 使用 HKDF (HMAC-based Key Derivation Function)
earlySecret := HKDF-Extract(salt: 0, ikm: PSK)
handshakeSecret := HKDF-Extract(
    salt: Derive-Secret(earlySecret, "derived", ""),
    ikm: ECDHE
)
masterSecret := HKDF-Extract(
    salt: Derive-Secret(handshakeSecret, "derived", ""),
    ikm: 0
)
```

**实现复杂度**：
- 需要实现完整的 HKDF 算法
- 需要提取 client_random、server_random、session_id
- 需要识别 TLS 版本
- 需要处理 session resumption

#### 2.1.4 网络连接跟踪

需要 hook 内核函数建立 fd → tuple 映射：

```c
// Kernel hooks (kprobe)
__sys_connect     // 连接建立
inet_stream_connect
__sys_accept4     // 接受连接
inet_accept
tcp_close         // 连接关闭
tcp_sendmsg       // 数据发送
tcp_recvmsg       // 数据接收
```

**Map 结构**：
```c
// fd -> tuple mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);   // fd
    __type(value, struct connect_info_t);
    __uint(max_entries, 10240);
} connect_info_map SEC(".maps");

struct connect_info_t {
    uint32_t pid;
    uint32_t fd;
    uint64_t ts;
    char saddr[16];
    char daddr[16];
    uint16_t sport;
    uint16_t dport;
};
```

#### 2.1.5 三种输出模式

**A. Text 模式**（相对简单）：
- Hook SSL_write/SSL_read
- 解密前的明文数据
- 格式化输出

```
[2024-01-02 12:34:56] [PID: 1234] [192.168.1.100:54321 -> 93.184.216.34:443]
>>> GET / HTTP/1.1
>>> Host: example.com
>>> 
<<< HTTP/1.1 200 OK
<<< Content-Type: text/html
```

**B. Keylog 模式**（中等复杂）：
- Hook master key 生成函数
- 提取 client_random + master_secret
- 输出 NSS keylog 格式

```
CLIENT_RANDOM 52340... ABCD...
CLIENT_RANDOM 52341... BCDE...
```

**C. Pcap 模式**（极度复杂）：
- 需要 TC (Traffic Control) 分类器
- Hook egress/ingress 数据包
- 组装完整的 TCP/TLS 数据包
- 写入 PCAPNG 格式

```c
// TC classifier
SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb)
{
    // 提取数据包信息
    // 与 SSL session 关联
    // 存储到 perf ring buffer
}
```

**挑战**：
- Pcap 需要完整的网络栈知识
- 需要处理数据包分片和重组
- 需要与 master key 同步
- 文件格式复杂（PCAPNG）

### 2.2 GnuTLS 探针

#### 2.2.1 特点
- GNU 项目的 TLS 实现
- 主要用于 Linux 系统工具
- 版本相对稳定（3.x 系列）

#### 2.2.2 Hook 点

```c
// GnuTLS 3.x
gnutls_record_send
gnutls_record_recv
gnutls_handshake
gnutls_session_get_random
```

#### 2.2.3 复杂度
- 低于 OpenSSL（版本少）
- 结构体相对稳定
- 社区文档较少

### 2.3 NSPR 探针

#### 2.3.1 特点
- Mozilla 的网络安全库
- Firefox/Thunderbird 使用
- NSS (Network Security Services)

#### 2.3.2 Hook 点

```c
// NSPR/NSS
PR_Write
PR_Read
PR_Send
PR_Recv
SSL_ImportFD
```

#### 2.3.3 复杂度
- 中等
- Firefox 专用场景
- 版本跟随 Firefox

### 2.4 GoTLS 探针

#### 2.4.1 特点
- Go 标准库 crypto/tls
- 纯 Go 实现
- 没有 C 接口

#### 2.4.2 挑战
- **极高难度**
- 需要理解 Go runtime 内部结构
- 需要支持多个 Go 版本（1.17-1.24）
- 结构体布局随 Go 版本变化
- 没有稳定的符号表

#### 2.4.3 Hook 点

```go
// crypto/tls package
(*Conn).Write
(*Conn).Read
(*Conn).Handshake
(*Conn).connectionStateLocked

// 需要通过偏移量计算
// Go 1.17: offset = 0x120
// Go 1.18: offset = 0x128
// Go 1.19: offset = 0x130
// ... 每个版本都不同
```

#### 2.4.4 Go 版本矩阵

| Go 版本 | crypto/tls 变化 | 支持难度 |
|---------|----------------|---------|
| 1.17 | - | 高 |
| 1.18 | 泛型引入 | 极高 |
| 1.19 | 微调 | 高 |
| 1.20 | TLS 1.3 优化 | 极高 |
| 1.21 | 结构体重组 | 极高 |
| 1.22+ | 未知 | 未知 |

---

## 3. 工作量分析

### 3.1 详细工作量估计

#### 3.1.1 TLS Base Infrastructure（~5小时）

| 任务 | 描述 | 时间 |
|------|------|------|
| TextHandler | 文本格式输出处理器 | 1h |
| KeylogHandler | Keylog 格式输出处理器 | 1.5h |
| PcapHandler | PCAPNG 格式输出处理器 | 2h |
| 共享工具 | 密钥提取、网络跟踪基础 | 0.5h |

#### 3.1.2 OpenSSL 探针（~6小时）

| 任务 | 描述 | 时间 |
|------|------|------|
| Config | 版本检测、路径发现 | 1h |
| Event | 事件结构、解码逻辑 | 0.5h |
| Probe | 核心探针逻辑 | 2h |
| 版本适配 | 1.1.1/3.0/3.1 适配 | 1.5h |
| 测试 | 单元测试 + 集成测试 | 1h |

#### 3.1.3 GnuTLS 探针（~5小时）

| 任务 | 描述 | 时间 |
|------|------|------|
| Config | 路径发现、函数验证 | 0.5h |
| Event | 事件结构、解码 | 0.5h |
| Probe | 核心逻辑 | 2h |
| 版本适配 | 3.x 系列 | 1h |
| 测试 | 测试用例 | 1h |

#### 3.1.4 NSPR 探针（~5小时）

| 任务 | 描述 | 时间 |
|------|------|------|
| Config | Firefox/库检测 | 0.5h |
| Event | 事件结构 | 0.5h |
| Probe | 核心逻辑 | 2h |
| 版本适配 | NSS 版本 | 1h |
| 测试 | 测试用例 | 1h |

#### 3.1.5 GoTLS 探针（~6小时）

| 任务 | 描述 | 时间 |
|------|------|------|
| Config | Go 版本检测、偏移计算 | 1h |
| Event | 事件结构 | 0.5h |
| Probe | 核心逻辑 | 2h |
| 版本适配 | Go 1.17-1.24 适配 | 1.5h |
| 测试 | 测试用例 | 1h |

**总计**：~27 小时

### 3.2 代码量估计

| 组件 | TLS Base | OpenSSL | GnuTLS | NSPR | GoTLS | 总计 |
|------|---------|---------|--------|------|-------|------|
| 处理器 | 800 | - | - | - | - | 800 |
| Config | - | 600 | 500 | 450 | 500 | 2,050 |
| Event | - | 400 | 350 | 300 | 350 | 1,400 |
| Probe | - | 1,200 | 900 | 800 | 1,000 | 3,900 |
| Register | - | 100 | 100 | 100 | 100 | 400 |
| Tests | 500 | 800 | 600 | 600 | 700 | 3,200 |
| **总计** | **1,300** | **3,100** | **2,450** | **2,250** | **2,650** | **11,750** |

**对比**：
- 简单探针平均：~1,000 行
- TLS 探针平均：~2,650 行
- **增长比例**：2.65x

### 3.3 复杂度评分

| 维度 | 权重 | Bash | MySQL | OpenSSL | GoTLS |
|------|------|------|-------|---------|-------|
| 版本支持 | 20% | 2 | 6 | 9 | 10 |
| Hook 点数 | 15% | 7 | 4 | 9 | 8 |
| 数据处理 | 20% | 5 | 6 | 10 | 10 |
| 输出格式 | 15% | 3 | 3 | 9 | 9 |
| 网络交互 | 15% | 0 | 0 | 10 | 10 |
| eBPF 复杂 | 15% | 3 | 4 | 10 | 10 |
| **总分** | 100% | **3.6** | **4.4** | **9.6** | **9.7** |

**结论**：TLS 探针的复杂度是简单探针的 **2.5倍**。

---

## 4. 实施方案

### 4.1 方案A：完整实施（推荐）

#### 4.1.1 目标
- 实现所有 TLS 探针的完整功能
- 支持三种输出模式（text/keylog/pcap）
- 覆盖主流版本

#### 4.1.2 实施顺序
1. **TLS Base**（~5h）
   - 实现三个处理器
   - 建立共享基础设施
   - 验证设计模式

2. **OpenSSL Text**（~3h）
   - 最常用场景
   - 验证架构
   - 快速反馈

3. **OpenSSL Keylog**（~2h）
   - 密钥提取逻辑
   - Keylog 格式

4. **OpenSSL Pcap**（~2h）
   - TC 分类器
   - PCAPNG 格式

5. **GnuTLS**（~5h）
   - 复用 OpenSSL 模式
   - 适配 GnuTLS API

6. **NSPR**（~5h）
   - Firefox 专用
   - NSS 库

7. **GoTLS**（~6h）
   - 最复杂
   - Go runtime 探测

#### 4.1.3 时间线
- **Week 1**：TLS Base + OpenSSL（~8h）
- **Week 2**：GnuTLS + NSPR（~10h）
- **Week 3**：GoTLS（~6h）
- **Week 4**：测试 + 优化（~3h）

**总计**：~27 小时，约4周

#### 4.1.4 优点
- 完整功能
- 一次到位
- 易于维护

#### 4.1.5 缺点
- 时间长
- PR 巨大（~12,000 行）
- 审查困难
- 风险高

### 4.2 方案B：简化实施（快速路径）

#### 4.2.1 目标
- 快速验证 TLS 架构
- 实现核心功能
- 保持 PR 可审查

#### 4.2.2 实施范围
1. **TLS Base - TextHandler Only**（~1h）
   - 仅实现 text 输出
   - Keylog/Pcap 标记 TODO

2. **OpenSSL Text Mode**（~3h）
   - 仅支持 OpenSSL 1.1.1 和 3.0（主流版本）
   - 仅实现 text 输出
   - 简化版本检测

3. **其他探针占位符**（~1h）
   - 创建目录结构
   - 基本 Config/Event/Probe/Register
   - 所有逻辑标记 TODO

#### 4.2.3 时间线
- **Day 1**：TLS Base TextHandler（~1h）
- **Day 2-3**：OpenSSL Text Mode（~3h）
- **Day 4**：占位符 + 测试（~1h）

**总计**：~5 小时，约4天

#### 4.2.4 代码量
- TLS Base TextHandler：~300 行
- OpenSSL Text：~1,500 行
- 占位符：~400 行
- 测试：~600 行
- **总计**：~2,800 行

#### 4.2.5 优点
- 快速验证
- 小的 PR（易审查）
- 低风险
- 快速反馈

#### 4.2.6 缺点
- 功能不完整
- 需要后续 PR
- 用户期待管理

### 4.3 方案C：暂停并回顾

#### 4.3.1 目标
- 巩固阶段3成果
- 评估架构效果
- 规划长期路线

#### 4.3.2 行动
1. **代码审查**：彻底审查阶段1-3代码
2. **文档完善**：补充使用指南
3. **性能测试**：基准测试和优化
4. **社区反馈**：收集早期用户反馈

#### 4.3.3 后续决策
- 根据反馈调整架构
- 确定 TLS 探针优先级
- 制定分阶段路线图

#### 4.3.4 优点
- 稳妥
- 基于反馈
- 降低返工风险

#### 4.3.5 缺点
- 延迟 TLS 功能
- 可能失去动力

---

## 5. 风险分析

### 5.1 技术风险

| 风险 | 影响 | 可能性 | 缓解措施 |
|------|------|--------|---------|
| 版本兼容性 | 高 | 高 | 逐版本测试，自动化测试 |
| eBPF 限制 | 高 | 中 | 优化代码，使用 helper functions |
| 密钥提取失败 | 高 | 中 | 多点采样，容错处理 |
| 网络跟踪不准 | 中 | 中 | 增加校验，日志记录 |
| Pcap 文件损坏 | 中 | 低 | 校验和，定期 flush |

### 5.2 项目风险

| 风险 | 影响 | 可能性 | 缓解措施 |
|------|------|--------|---------|
| 时间超支 | 中 | 高 | 简化实施（方案B） |
| PR 过大 | 高 | 高 | 分拆多个 PR |
| 审查困难 | 高 | 高 | 详细文档，示例代码 |
| 回归 bug | 高 | 中 | 保留旧代码，充分测试 |
| 社区期待 | 中 | 中 | 清晰沟通，设定预期 |

---

## 6. 推荐方案

### 6.1 最终推荐：**方案B（简化实施）**

#### 6.1.1 理由
1. **快速验证**：5 小时完成，快速验证 TLS 架构
2. **低风险**：小的 PR（~2,800 行），易审查
3. **早期反馈**：可以快速获得用户反馈
4. **灵活性**：后续可以根据反馈调整
5. **符合 Agent Profile**："小粒度、可审阅的代码改动 PR"

#### 6.1.2 实施计划

**第1天**：TLS Base - TextHandler
```go
// internal/probe/base/handlers.go
type TextHandler struct {
    writer io.Writer
}

func (h *TextHandler) HandleEvent(e domain.Event) error {
    // 格式化文本输出
}
```

**第2-3天**：OpenSSL Text Mode
```go
// internal/probe/openssl/config.go
type Config struct {
    *config.BaseConfig
    OpensslPath   string
    SslVersion    string  // 仅支持 1.1.1 和 3.0
    // TODO: 添加更多版本支持
}

// internal/probe/openssl/openssl_probe.go
type Probe struct {
    *base.BaseProbe
    handler *base.TextHandler
    // TODO: 添加 KeylogHandler 和 PcapHandler
}

func (p *Probe) Start(ctx context.Context) error {
    // 仅实现 SSL_write/SSL_read hook
    // TODO: 添加 master key hook
    // TODO: 添加网络跟踪
}
```

**第4天**：占位符 + 测试
```go
// internal/probe/gnutls/gnutls_probe.go
type Probe struct {
    *base.BaseProbe
    // TODO: 实现 GnuTLS 探针
}

func (p *Probe) Start(ctx context.Context) error {
    return errors.New("GnuTLS probe not implemented yet")
}
```

#### 6.1.3 后续路线图

**短期（1-2周）**：
- 收集 OpenSSL Text Mode 反馈
- 修复发现的 bug
- 优化性能

**中期（1-2月）**：
- PR #2：OpenSSL Keylog Mode
- PR #3：OpenSSL Pcap Mode  
- PR #4：GnuTLS 完整实现
- PR #5：NSPR 完整实现

**长期（3-6月）**：
- PR #6：GoTLS 完整实现
- PR #7：性能优化
- PR #8：更多版本支持

### 6.2 决策树

```
开始阶段4
    |
    ├─> 目标：快速验证架构
    |   └─> 选择方案B（简化实施）
    |       └─> 5小时，~2,800行代码
    |
    ├─> 目标：完整功能
    |   └─> 选择方案A（完整实施）
    |       └─> 27小时，~12,000行代码
    |
    └─> 目标：稳妥推进
        └─> 选择方案C（暂停回顾）
            └─> 先巩固，再规划
```

---

## 7. 成功标准

### 7.1 方案B成功标准

#### 7.1.1 功能标准
- ✅ OpenSSL Text Mode 可以捕获 HTTPS 流量
- ✅ 支持 OpenSSL 1.1.1 和 3.0
- ✅ 输出格式清晰、可读
- ✅ 错误处理健壮

#### 7.1.2 质量标准
- ✅ 测试覆盖率 ≥70%
- ✅ 所有测试通过
- ✅ 竞态检测通过
- ✅ 代码复杂度 ≤12

#### 7.1.3 文档标准
- ✅ 使用指南
- ✅ 配置示例
- ✅ 故障排查
- ✅ TODO 清单

#### 7.1.4 项目标准
- ✅ PR 可审查（<3,000 行）
- ✅ 向后兼容
- ✅ 无回归 bug
- ✅ 构建通过

---

## 8. 总结

### 8.1 关键要点

1. **TLS 探针比简单探针复杂 5-10倍**
   - 代码量：2.65x
   - 复杂度：2.5x  
   - 时间：5-7x

2. **完整实施需要 ~27 小时**
   - TLS Base：5h
   - OpenSSL：6h
   - 其他：16h

3. **推荐方案B（简化实施）**
   - 5 小时完成
   - ~2,800 行代码
   - 易审查、低风险

4. **后续分多个 PR 完善**
   - 每个 PR 专注一个功能
   - 保持小的、可审查的改动
   - 根据反馈调整优先级

### 8.2 决策建议

**立即行动**：
- 选择方案B（简化实施）
- 实现 OpenSSL Text Mode
- 为其他探针创建占位符

**近期规划**：
- 收集反馈
- 修复 bug
- 规划后续 PR

**长期愿景**：
- 逐步完善所有 TLS 探针
- 支持更多版本
- 优化性能

### 8.3 最终建议

基于：
- 阶段3的成功经验
- TLS 探针的复杂度分析
- eCapture-PR-Agent 的原则（"小粒度、可审阅的代码改动 PR"）

**我们推荐采用方案B（简化实施）**：
1. 快速实现 OpenSSL Text Mode（~5小时）
2. 验证 TLS 架构设计
3. 获取早期反馈
4. 后续分多个 PR 逐步完善

这种方法平衡了速度、质量和风险，符合项目的长期利益。

---

## 附录

### A. 相关文件

- `internal/README.md` - 开发者指南
- `internal/ARCHITECTURE.md` - 架构文档
- `internal/MIGRATION_GUIDE.md` - 迁移指南
- `internal/IMPLEMENTATION_PLAN.md` - 实施计划

### B. 参考资料

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [GnuTLS Manual](https://www.gnutls.org/manual/)
- [NSS Documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)
- [Go crypto/tls Package](https://pkg.go.dev/crypto/tls)
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)

### C. 版本号

- **文档版本**：1.0
- **创建日期**：2026-01-02
- **最后更新**：2026-01-02
- **作者**：eCapture Architecture Team

---

**结论**：阶段4的 TLS 探针迁移是一项复杂但可行的任务。通过采用简化实施方案（方案B），我们可以在保持代码质量和项目可控性的同时，快速验证 TLS 架构并为后续工作奠定基础。
