# 预发布版本指南

本指南说明当前 [发布 workflow](../.github/workflows/release.yml) 和
[发布 Makefile](../builder/Makefile.release) 的版本约定。它面向有发布权限的维护者。

## Tag 与发布类型

| 类型 | Tag 示例 | GitHub Release | Docker 标签 |
| --- | --- | --- | --- |
| Alpha | `v2.10.0-alpha.1` | Pre-release | 版本标签 |
| Beta | `v2.10.0-beta.1` | Pre-release | 版本标签 |
| RC | `v2.10.0-rc.1` | Pre-release | 版本标签 |
| 正式版 | `v2.10.0` | 普通 Release | 版本标签与 `latest` |

上表中的版本号仅为命名示例。Workflow 在推送 `v*` tag 时触发：

- `v数字.数字.数字` 被识别为正式版。
- 其他包含 `alpha`、`beta` 或 `rc` 的 tag 被识别为预发布版。
- 其余 `v*` tag 也会落入正式版分支，因此不要使用 `v2-dev` 等非约定格式。

预发布版通过 `IS_PRERELEASE=true` 传给发布 Makefile，由其调用
`gh release create --prerelease`；Docker 发布也使用同一判断，不更新 `latest`。

## 发布流程

先完成 [构建与验证要求](agent/build-test.md)，确认发布提交和预期 tag。
在该提交上创建并推送一个尚未使用的 tag，例如：

```bash
RELEASE_TAG="v2.10.0-beta.1"
git tag "$RELEASE_TAG"
git push origin "$RELEASE_TAG"
```

发布工作流在同一个 Ubuntu 24.04 作业中构建 Linux amd64、arm64、loong64
包，其中 loong64 使用 LLVM 22.1.8；Android 构建限于 amd64、arm64。
Docker 镜像发布 amd64、arm64 两种架构。

Loong64 步骤设置了 `continue-on-error`：构建或产物审计失败时会移除对应包，
继续发布已验证的 amd64/arm64 产物。因此，作业成功不代表三种架构的包都已发布。

发布后检查：

1. 检查 GitHub Actions 作业及 Loong64 步骤的结果，确认实际发布的架构；
   Release 的版本及 Pre-release 标记正确。
2. 包列表与实际成功的架构相符，存在 `checksum-<tag>.txt`，并按
   [发布校验指南](release-verification.md) 检查下载包。
3. Docker 版本标签存在；预发布没有更新 `latest`。

修正已发布版本时，建议使用新的版本 tag，避免让同一版本名称对应不同内容。
