# 测试策略与 CI/CD

## 测试体系

eCapture 采用多层测试体系，覆盖单元测试、端到端测试和安全扫描。

### 单元测试

使用 Go 标准测试框架，覆盖核心组件：

```bash
# 运行所有单元测试（竞态检测）
make test-race
# 等价于：go test -race -tags dynamic,ebpfassets ./...
```

主要测试文件：

| 测试文件 | 覆盖组件 |
|---------|---------|
| `pkg/event_processor/processor_test.go` | EventProcessor 调度逻辑 |
| `pkg/event_processor/http2_request_test.go` | HTTP/2 请求解析 |
| `pkg/event_processor/http2_response_test.go` | HTTP/2 响应解析 |
| `pkg/event_processor/http_response_test.go` | HTTP/1.1 响应解析 |
| `internal/factory/probe_factory_test.go` | 探针工厂注册与创建 |
| `internal/probe/base/base_probe_test.go` | BaseProbe 基类逻辑 |

### 端到端测试（E2E）

E2E 测试在真实 Linux 内核上运行，验证 eCapture 能够成功捕获各类系统活动。

#### 前提条件

- Linux 内核 ≥4.18（x86_64）或 ≥5.5（aarch64）
- ROOT 权限
- 相关工具（openssl、curl、go 编译器等）

#### 运行方式

```bash
# 运行所有 E2E 测试
sudo make e2e

# 运行基础测试（bash, tls, gnutls, gotls）
sudo make e2e-basic

# 运行高级测试（pcap/keylog/text 各模式）
sudo make e2e-advanced

# 运行单个模块测试
sudo make e2e-bash
```

#### 测试模块

| 模块 | 测试内容 |
|------|---------|
| Bash | bash 命令捕获 |
| Zsh | zsh 命令捕获 |
| TLS | OpenSSL/BoringSSL 流量捕获 |
| GnuTLS | GnuTLS 库流量捕获 |
| GoTLS | Go 原生 TLS 实现捕获 |
| MySQL | MySQL 查询捕获 |
| PostgreSQL | PostgreSQL 查询捕获 |

#### 测试框架

E2E 测试位于 `test/e2e/` 目录，使用 shell 脚本实现：

- `common.sh`：共享的辅助函数（内核版本检查、root 检查、超时助手）
- 每个模块一个测试脚本

## CI/CD 流程

### GitHub Actions Workflows

| Workflow 文件 | 说明 |
|--------------|------|
| `e2e.yml` | E2E 测试（多架构） |
| `android_e2e.yml` | Android E2E 测试 |
| `codeql-analysis.yml` | CodeQL 安全扫描 |
| `go-c-cpp.yml` | Go/C/C++ 代码质量检查 |
| `pr_build_debug.yml` | PR 调试构建 |
| `release.yml` | 自动发布流程 |

### CI 构建矩阵

- **架构**：x86_64、arm64
- **内核版本**：多版本覆盖
- **构建模式**：CO-RE、非 CO-RE

### CodeQL 安全扫描

使用 GitHub CodeQL 对 Go 和 C 代码进行自动化安全分析，检测常见的安全漏洞模式。

### 自动发布流程

1. 创建 Git tag 触发 `release.yml`
2. 多架构构建（x86_64 + arm64）
3. 打包为多种格式：tar.gz、RPM（通过 `rpmBuild.spec`）、DEB
4. 构建 Docker 镜像并推送到 Docker Hub
5. 创建 GitHub Release 并上传所有构建产物

发布相关文件：

| 文件 | 说明 |
|------|------|
| `builder/Makefile.release` | 发布构建逻辑 |
| `builder/rpmBuild.spec` | RPM 打包规格 |
| `builder/Dockerfile` | Docker 镜像构建 |

## Lint 检查

```bash
# Go lint（使用 golangci-lint）
golangci-lint run --build-tags ebpfassets

# C 代码格式化（Google 风格，120 列）
make format
```

## 测试最佳实践

1. **添加新功能时**：同时添加单元测试（`_test.go`）
2. **修改 eBPF 程序时**：在支持的内核上运行 E2E 测试验证
3. **修改事件解析器时**：使用 `testdata/` 目录中的测试数据验证解析正确性
4. **提交 PR 前**：运行 `make test-race` 确保单元测试通过
