# Android E2E Tests - 快速开始指南

## 简介

本指南帮助您快速开始在Android设备上运行eCapture的e2e测试。

## 前置条件

### 必需项
- ✅ Android 15+ (API 35+) 设备或模拟器
- ✅ ARM64 架构
- ✅ Linux 内核 5.5+
- ✅ Root 权限
- ✅ ADB (Android Debug Bridge)
- ✅ Linux 构建环境（用于编译）

### 可选项
- 设备上的 curl 或 wget（用于TLS测试）
- Go 1.21+（用于构建Go测试客户端）

## 三步快速开始

### 步骤 1: 编译 Android 版本

**在 Linux 服务器上：**

```bash
cd /home/cfc4n/project/ecapture
ANDROID=1 make nocore
```

**从 macOS 远程编译：**

```bash
# 在远程Linux服务器编译
ssh cfc4n@172.16.71.128 'cd /home/cfc4n/project/ecapture && ANDROID=1 make nocore'

# 下载编译好的二进制
scp cfc4n@172.16.71.128:/home/cfc4n/project/ecapture/bin/ecapture bin/
```

### 步骤 2: 连接 Android 设备

**物理设备：**

```bash
# 1. 开启开发者选项（连续点击"版本号"7次）
# 2. 开启USB调试
# 3. 连接USB线
adb devices
```

**模拟器：**

```bash
# 安装Android SDK命令行工具
brew install --cask android-commandlinetools  # macOS

# 下载系统镜像
sdkmanager "system-images;android-35;google_apis;arm64-v8a"

# 创建AVD
avdmanager create avd -n android15_test \
  -k "system-images;android-35;google_apis;arm64-v8a"

# 启动模拟器
emulator -avd android15_test -writable-system -no-snapshot-save &

# 获取root权限
adb root
adb wait-for-device
```

### 步骤 3: 运行测试

```bash
# 验证环境
make setup-android-env

# 运行所有测试
make e2e-android-all

# 或运行单个测试
make e2e-android-tls      # TLS模块测试
make e2e-android-gotls    # GoTLS模块测试
make e2e-android-bash     # Bash模块测试
```

## 常见问题快速解决

### 问题 1: "No Android device connected"

```bash
# 重启ADB
adb kill-server
adb start-server
adb devices
```

### 问题 2: "Failed to get root access"

```bash
# 模拟器
adb root

# 物理设备需要已经root
# 使用Magisk或其他root工具
```

### 问题 3: "SELinux is in Enforcing mode"

```bash
# 设置为宽容模式
adb shell setenforce 0

# 验证
adb shell getenforce  # 应显示 "Permissive"
```

### 问题 4: "Binary is not ARM64"

```bash
# 必须在Linux上用ANDROID=1编译
ANDROID=1 make nocore

# 验证架构
file bin/ecapture  # 应显示 "ARM aarch64"
```

### 问题 5: "curl not found on device"

```bash
# 使用带有网络工具的系统镜像
# 例如 google_apis 而不是 default

# 或安装busybox到设备
```

## 测试输出示例

### 成功输出
```
[INFO] === Android TLS E2E Test ===
[INFO] Target URL: https://www.google.com
[SUCCESS] All prerequisites met
[SUCCESS] ecapture deployed successfully
[SUCCESS] ✓ Test 1 PASSED: Found HTTP plaintext in output
[SUCCESS] ✓ Test 2 PASSED: PCAP file created successfully
[SUCCESS] ✓ Test 3 PASSED: PID filter test completed
[SUCCESS] All 3 tests PASSED
```

### 查看日志
```bash
# 测试日志保存在本地临时目录
ls -la /tmp/ecapture_android_*

# 查看最新日志
tail -100 /tmp/ecapture_android_tls_*/ecapture.log
```

## 测试架构图

```
┌─────────────────────────────────────────┐
│         macOS 开发环境                    │
│  - 编写代码                               │
│  - 运行ADB命令                            │
│  - 查看测试结果                           │
└─────────────┬───────────────────────────┘
              │ SSH
              ▼
┌─────────────────────────────────────────┐
│      Linux 构建服务器                     │
│  - 编译 Android ARM64 二进制              │
│  - ANDROID=1 make nocore                │
└─────────────┬───────────────────────────┘
              │ ADB over USB/Network
              ▼
┌─────────────────────────────────────────┐
│     Android 设备/模拟器                   │
│  - Android 15+ (API 35+)                │
│  - ARM64 架构                            │
│  - Root 权限                             │
│  - 运行 ecapture                         │
│  - 捕获 TLS/Bash 流量                    │
└─────────────────────────────────────────┘
```

## 详细文档

- 📖 [完整README](./README.md) - 详细使用说明
- 📋 [实现总结](./IMPLEMENTATION_SUMMARY.md) - 技术细节
- 🔧 [环境设置脚本](./setup_android_env.sh) - 自动验证
- 🏗️ [构建脚本](./build_android_tests.sh) - 自动编译

## GitHub Actions 集成

测试也可以在CI/CD中自动运行：

```yaml
# .github/workflows/android_e2e.yml
# 触发条件：
# - Push到 master/v2 分支
# - Pull Request
# - 手动触发
```

手动触发：GitHub UI → Actions → Android E2E Tests → Run workflow

## 下一步

1. ✅ 阅读完整 [README.md](./README.md)
2. ✅ 运行 `setup_android_env.sh` 验证环境
3. ✅ 执行单个测试模块熟悉流程
4. ✅ 查看测试脚本源码了解实现
5. ✅ 根据需要添加自定义测试

## 技术支持

遇到问题？

1. 检查本指南的常见问题部分
2. 运行 `bash test/e2e/android/setup_android_env.sh` 诊断
3. 查看测试日志 `/tmp/ecapture_android_*`
4. 在GitHub提交issue并附上：
   - Android版本: `adb shell getprop ro.build.version.release`
   - 内核版本: `adb shell uname -r`
   - 测试输出和错误日志

---

**提示**: 首次运行建议使用Android模拟器，更容易获取root权限且环境可重现。
