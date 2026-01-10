# eCapture Documentation

This directory contains comprehensive documentation for the eCapture project.

## Documentation Index

### Getting Started
- [**compilation.md**](compilation.md) - Build and compilation guide (English)
- [**compilation-cn.md**](compilation-cn.md) - 编译指南 (中文)

### Architecture & Development
- [**refactoring-guide.md**](refactoring-guide.md) - Probe refactoring patterns and best practices
- [**probe-refactoring-playbook.md**](probe-refactoring-playbook.md) - Detailed refactoring tutorial with step-by-step instructions
- [**migration-v2.md**](migration-v2.md) - Migration guide from v1 to v2 architecture
- [**gotls-refactoring-summary.md**](gotls-refactoring-summary.md) - GoTLS probe refactoring case study

### Testing
- [**e2e-tests.md**](e2e-tests.md) - End-to-end testing guide

### API Documentation
- [**event-forward-api.md**](event-forward-api.md) - Event forwarding API documentation (English)
- [**event-forward-api_CN.md**](event-forward-api_CN.md) - 事件转发API文档 (中文)
- [**remote-config-update-api.md**](remote-config-update-api.md) - Remote configuration update API (English)
- [**remote-config-update-api_CN.md**](remote-config-update-api_CN.md) - 远程配置更新API (中文)

### Integration
- [**event-forward.md**](event-forward.md) - Event forwarding applications and GUI clients

## Document Organization

### Root Directory (`/`)
The project root contains standard GitHub community health files:
- `README.md` - Project overview and quick start
- `CONTRIBUTING.md` - Contribution guidelines
- `CODE_OF_CONDUCT.md` - Community code of conduct
- `SECURITY.md` - Security policy
- `CHANGELOG.md` - Release history

### Docs Directory (`/docs`)
Technical documentation, guides, and API references are organized here.

### Internal Directory (`/internal`)
Contains architecture documentation for internal packages (see `internal/README.md`).

## Naming Convention

All documentation files in this directory follow the **lowercase-with-hyphens** (kebab-case) naming convention for consistency and web compatibility.

Examples:
- ✅ `refactoring-guide.md`
- ✅ `e2e-tests.md`
- ✅ `event-forward-api.md`

## Contributing to Documentation

When adding new documentation:
1. Place it in the appropriate directory (`/docs` for technical docs, `/` for community files)
2. Use lowercase with hyphens for file names
3. Update this README to include your new document
4. Ensure proper cross-references to related documents

## Language Versions

Chinese versions of documents are indicated with a `-cn` suffix:
- `compilation.md` (English) / `compilation-cn.md` (中文)
- `event-forward-api.md` (English) / `event-forward-api_CN.md` (中文)

Japanese versions use `-ja` suffix:
- `README.md` (English) / `README_JA.md` (日本語)

