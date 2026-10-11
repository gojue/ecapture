# Beta/预发布版本指南

## 📋 Tag 命名规范

本项目已支持自动识别并处理预发布版本。请按照以下规范命名 Git tags：

### 预发布版本（Pre-release）

- **Beta 版本**: `v2.0.0-beta.1`, `v2.0.0-beta.2`, `v2.1.0-beta.1`
- **Alpha 版本**: `v2.0.0-alpha.1`, `v2.0.0-alpha.2`
- **RC (Release Candidate) 版本**: `v2.0.0-rc.1`, `v2.0.0-rc.2`

### 正式版本（Stable）

- **正式发布**: `v2.0.0`, `v2.1.0`, `v1.8.13`

## 🔄 发布流程

### 发布 Beta 版本

```bash
# 1. 确保代码已提交
git add .
git commit -m "feat: v2 beta features"

# 2. 创建 beta tag
git tag v2.0.0-beta.1

# 3. 推送 tag 到远程仓库（触发自动构建和发布）
git push origin v2.0.0-beta.1
```

### 发布正式版本

```bash
# 1. 创建正式版本 tag
git tag v2.0.0

# 2. 推送 tag
git push origin v2.0.0
```

## 🎯 自动化处理

当你推送 tag 后，GitHub Actions 会自动：

### 预发布版本（包含 alpha/beta/rc）

✅ 在 GitHub Releases 中标记为 **Pre-release**  
✅ 构建 Linux amd64/arm64/loong64 版本（loong64 使用独立 Ubuntu 24.04/LLVM 18 作业）
✅ 构建 Android 版本  
✅ 构建 Docker 镜像（仅标记版本号，**不标记** `latest`）  
✅ 生成 Release Notes  
✅ 上传所有构建产物  

Docker 镜像标签示例：
- ✅ `ecapture:v2.0.0-beta.1`
- ❌ `ecapture:latest` (不会更新)

### 正式版本（标准语义化版本）

✅ 在 GitHub Releases 中标记为 **Latest Release**  
✅ 构建所有平台版本  
✅ 构建 Docker 镜像（标记版本号 **和** `latest`）  
✅ 生成 Release Notes  
✅ 上传所有构建产物  

Docker 镜像标签示例：
- ✅ `ecapture:v2.0.0`
- ✅ `ecapture:latest` (更新到最新稳定版)

## 📦 版本示例

### v2 开发阶段建议

```bash
# 第一个 alpha 版本
v2.0.0-alpha.1

# 功能逐步完善
v2.0.0-alpha.2
v2.0.0-alpha.3

# 进入 beta 测试阶段
v2.0.0-beta.1
v2.0.0-beta.2

# 发布候选版本
v2.0.0-rc.1
v2.0.0-rc.2

# 正式发布
v2.0.0

# 后续版本
v2.0.1  # bug 修复
v2.1.0  # 新功能
v2.1.0-beta.1  # 下一个版本的 beta
```

## 🔍 验证发布类型

workflow 使用以下逻辑识别版本类型：

```bash
# 正式版本（匹配 v数字.数字.数字）
v1.2.3 ✅
v2.0.0 ✅

# 预发布版本（包含 alpha、beta 或 rc）
v2.0.0-alpha.1 ✅
v2.0.0-beta.1 ✅
v2.0.0-rc.1 ✅
v2.1.0-beta.2 ✅

# 其他格式会被识别为正式版本
v2.0.0.1 → 正式版本
v2-dev → 正式版本
```

## ⚙️ 技术细节

### Workflow 变更

修改文件：`.github/workflows/release.yml`

#### Linux/Android 构建作业
- 新增 `Check Release Type` 步骤
- 自动检测 tag 名称中是否包含 `alpha`, `beta`, `rc`
- 设置环境变量 `IS_PRERELEASE` 传递给构建脚本

#### Docker 构建作业
- 新增 `Check Release Type` 步骤
- 新增 `Prepare Docker Tags` 步骤
- 仅在正式版本时标记 `latest`

### Makefile 变更

修改文件：`builder/Makefile.release`

- 修改 `publish` 目标，读取 `IS_PRERELEASE` 环境变量
- 预发布版本使用 `--prerelease` 标志创建 GitHub Release

## 📝 注意事项

1. **删除 tag**: 如果需要重新发布，先删除远程和本地 tag
   ```bash
   git tag -d v2.0.0-beta.1
   git push origin :refs/tags/v2.0.0-beta.1
   ```

2. **版本号顺序**: Git/GitHub 会按语义化版本排序
   - `v2.0.0-alpha.1` < `v2.0.0-alpha.2` < `v2.0.0-beta.1` < `v2.0.0-rc.1` < `v2.0.0`

3. **Docker latest 标签**: 只有正式版本会更新 `latest`，用户使用 `docker pull ecapture:latest` 时不会拉取到测试版本

4. **GitHub UI**: 预发布版本在 Releases 页面会显示 "Pre-release" 标签，方便用户识别

## 🎉 开始使用

现在你可以开始发布 v2 的 beta 版本了：

```bash
git tag v2.0.0-beta.1
git push origin v2.0.0-beta.1
```

然后前往 GitHub Actions 查看构建进度，完成后在 Releases 页面查看发布的 beta 版本！
