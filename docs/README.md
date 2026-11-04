# eCapture documentation

Start with the project [README](../README.md) or
[中文说明](../README-zh_Hans.md) for supported capture modes and quick starts.

## Build and verification

- [Compilation](compilation.md) / [中文编译指南](compilation-zh_Hans.md)
- [Loong64 build, validation, and dedicated runner](loong64-support.md)
- [Build and test guide](agent/build-test.md): commands, platform boundaries,
  production tags, and verification requirements
- [E2E tests](../test/e2e/README.md) and
  [quick reference](../test/e2e/QUICK_REFERENCE.md): maintained Linux/Android
  coverage, prerequisites, assertions, and artifacts
- [Performance benchmarks](performance-benchmarks.md): OpenSSL userspace
  microbenchmarks and real-kernel TLS overhead/loss measurements
- [Pre-release conventions](beta-release-guide.md)
- [Release verification](release-verification.md)

## Architecture and development

- [Architecture](agent/architecture.md): runtime flow, package ownership,
  supported probes, and implementation boundaries
- [Probe development](agent/probe-development.md): attachment/ABI contracts,
  lifecycle, event reorder, configuration, and generated protocols
- [Output pipeline](agent/output-pipeline.md): representation, destinations,
  typed publishers, ownership, and validation contracts
- [Internal package map](../internal/README.md)
- [Repository agent guide](../AGENTS.md) and
  [contribution guide](../CONTRIBUTING.md)

## APIs and examples

- Event forwarding: [English](event-forward-api.md) /
  [中文](event-forward-api-zh_Hans.md)
- Runtime configuration: [English](remote-config-update-api.md) /
  [中文](remote-config-update-api-zh_Hans.md)
- [Protobuf protocols](../protobuf/PROTOCOLS.md) and
  [code generation](../protobuf/README.md)
- [eCaptureQ package](../pkg/ecaptureq/README.md) and
  [Go client example](../examples/ecaptureq_client/README.md)
- [Community integrations](event-forward.md)
- [Output examples](example-outputs.md)

## Security and operation

- [Minimum privileges](minimum-privileges.md)
- [Defense and detection](defense-detection.md)
- [Security policy](../SECURITY.md)

## Maintaining documentation

Keep long-lived behavior and commands with the relevant guide; use links
instead of duplicating architecture, test matrices, or protocol definitions.
Update this index when a maintained guide moves or is added. Check relative
links and keep English/Chinese versions synchronized. Historical task plans,
local validation evidence, and publication drafts are not current feature
specifications.
