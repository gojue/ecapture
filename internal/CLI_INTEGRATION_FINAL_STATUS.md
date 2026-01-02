# CLI 集成最终状态报告

## 当前状态

### 已完成 (4/8 探针)
根据维护者 @cfc4n 的反馈，已完全移除向后兼容逻辑，直接使用新架构：

1. **bash** (`cli/cmd/bash.go`) ✅
   - 移除 ECAPTURE_USE_NEW_ARCH 检查
   - 移除 user/config 和 user/module 依赖
   - 直接使用 internal/probe/bash
   
2. **zsh** (`cli/cmd/zsh.go`) ✅
   - 移除向后兼容代码
   - 直接使用 internal/probe/zsh
   
3. **mysqld** (`cli/cmd/mysqld.go`) ✅
   - 移除向后兼容代码
   - 直接使用 internal/probe/mysql
   
4. **postgres** (`cli/cmd/postgres.go`) ✅
   - 移除向后兼容代码
   - 直接使用 internal/probe/postgres

### 待完成 (4/8 探针)
TLS 探针需要进一步工作：

5. **nspr** (`cli/cmd/nspr.go`) ⏳
   - 配置结构：不扩展 BaseConfig
   - 字段：NSSPath, NSPRPath, CaptureMode, KeylogFile, PcapFile, Ifname, PcapFilter, PID
   
6. **gotls** (`cli/cmd/gotls.go`) ⏳
   - 配置结构：不扩展 BaseConfig
   - 字段：CaptureMode, KeylogFile, PcapFile, Ifname, PcapFilter, GoVersion, Pid
   
7. **gnutls** (`cli/cmd/gnutls.go`) ⏳
   - 配置结构：扩展 BaseConfig ✓
   - 字段：GnutlsPath, GnuVersion, CaptureMode, KeylogFile, PcapFile, Ifname, PcapFilter
   
8. **tls/openssl** (`cli/cmd/tls.go`) ⏳
   - 配置结构：需要确认
   - 最复杂的探针，支持多种模式

## 技术问题

### 配置不一致
不同探针的配置接口不统一：
- **简单探针** (bash, zsh, mysql, postgres): 扩展 BaseConfig
- **部分TLS探针** (nspr, gotls): 不扩展 BaseConfig，使用自定义PID字段
- **部分TLS探针** (gnutls): 扩展 BaseConfig

### globalConf 类型
- `cli/cmd/root.go` 中定义的 `globalConf` 类型是 `user/config.BaseConfig`
- 新探针使用的是 `internal/config.BaseConfig`
- 两者字段名称相同但是不同的类型
- 当前通过字段访问（如 `globalConf.Pid`）仍然可以工作

## 编译状态

### Go 代码
- 语法正确
- 类型检查通过（vet）
- 依赖 CGO，无法使用 CGO_ENABLED=0 编译

### eBPF 代码
- make 编译过程中有一些内核头文件警告
- 这些警告与 CLI 集成无关，是原有的 eBPF 代码问题

## 建议

### 短期
1. **统一配置接口**：让所有探针配置都扩展 BaseConfig
2. **提供迁移示例**：为 TLS 探针提供具体的迁移模式
3. **分阶段集成**：先完成简单探针，TLS 探针可以后续 PR

### 长期
1. **重构 root.go**：更新以使用新的 internal/config
2. **移除旧架构**：完全删除 user/config 和 user/module
3. **统一测试**：为所有集成的探针添加测试

## 文件变更

### 已修改
- `cli/cmd/bash.go`: 完全重写，使用新架构
- `cli/cmd/zsh.go`: 完全重写，使用新架构
- `cli/cmd/mysqld.go`: 完全重写，使用新架构
- `cli/cmd/postgres.go`: 完全重写，使用新架构
- `cli/cmd/event_dispatcher.go`: 新增，事件分发器

### 待修改
- `cli/cmd/nspr.go`: 需要迁移
- `cli/cmd/gotls.go`: 需要迁移
- `cli/cmd/gnutls.go`: 需要迁移
- `cli/cmd/tls.go`: 需要迁移
- `cli/cmd/root.go`: 需要更新依赖（长期）

## 下一步

1. 确认 TLS 探针的配置接口设计
2. 为未扩展 BaseConfig 的探针添加 SetPid/SetUid 等方法
3. 或者创建适配器函数来处理配置映射
4. 完成剩余 4 个探针的迁移
5. 运行完整的 make 编译测试
6. 添加 E2E 测试（需要 root 权限）

## Commit History
- 7502ebc: 移除向后兼容逻辑，完成 4 个探针迁移
- d8aa7f6: 添加 MySQL 和 PostgreSQL 集成（旧版本）
- 15b49c4: 添加 Zsh 集成（旧版本）
- c784b52: 添加 Bash 集成（旧版本）
