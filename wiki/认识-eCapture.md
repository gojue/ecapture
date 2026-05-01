# 认识 eCapture

**eCapture（旁观者）** 是一款基于 eBPF 技术实现的无需 CA 证书的明文流量捕获工具。其名取自「当局者迷，旁观者清」，与其旁路观察的功能定位高度契合。

eCapture 通过 eBPF `uprobe`/`kprobe`/`TC` 技术，在不修改目标程序、不安装 CA 证书的前提下，直接捕获 SSL/TLS 加密通讯的明文内容、数据库查询语句以及 Shell 命令。

---

## 本章内容

| 子页面 | 说明 |
|--------|------|
| [项目简介与核心能力](项目简介与核心能力) | eCapture 的背景定位、三大核心能力、与传统工具的对比以及典型使用场景 |
| [支持平台与版本说明](支持平台与版本说明) | 操作系统、内核版本要求、CO-RE 与非 CO-RE 模式、已验证发行版列表 |

---

## 快速了解

- **项目首页**：[https://ecapture.cc](https://ecapture.cc)
- **GitHub 仓库**：[https://github.com/gojue/ecapture](https://github.com/gojue/ecapture)
- **技术栈**：Go（用户态）+ C（eBPF 内核程序）+ Clang/LLVM 编译工具链
- **支持平台**：Linux x86_64（内核 ≥4.18）/ aarch64（内核 ≥5.5）、Android GKI
