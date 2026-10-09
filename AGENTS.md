# AGENTS.md — eCapture repository guide

This is the canonical repository guide for coding agents. Tool-specific files
such as `CLAUDE.md` and `.github/copilot-instructions.md` are compatibility
entry points, not separate sources of project truth.

## How to use this guide

- These instructions apply to the entire repository unless a deeper
  `AGENTS.md` narrows them.
- For runtime behavior, trust source code and tests. For build behavior, trust
  `go.mod`, `Makefile`, `variables.mk`, `functions.mk`, and current workflows.
  For maintained E2E behavior, trust `test/e2e/README.md` and its harness.
- For architecture/runtime/output work, read `docs/agent/architecture.md` and
  `docs/agent/output-pipeline.md`.
- For probes, ABI, CLI config, or generated protocols, read
  `docs/agent/probe-development.md`.
- For build, formatting, lint, tests, E2E, or CI, read
  `docs/agent/build-test.md`.
- Some older prose may lag the code or build files. This guide and current
  implementation win on factual conflicts.
- Keep this file and the relevant detailed guide synchronized when a change
  invalidates a command, path, invariant, or known limitation.

### Optional machine-local context

If `AGENTS.local.md` exists at the repository root, read it before choosing an
execution environment or running build, test, cross-compilation, or remote-host
operations. It may refine *where* commands run, but it must not override this
repository's safety, supported-platform, or verification requirements.

- `AGENTS.local.md` is optional and must remain uncommitted.
- Never require another contributor or a cloud agent to have it.
- Never copy its machine details into commits, logs, issues, or pull requests.
- Start from `AGENTS.local.example.md`; do not store credentials in either
  file.

## Non-negotiable platform boundary

eCapture may be edited anywhere, but compilation, linking, linting, tests,
eBPF generation, and execution require Linux. Android artifacts are also
built on a Linux host.

- Runtime targets: Linux and Android on `x86_64` or `aarch64`.
- Minimum kernels on both OS targets: x86_64 >= 4.18; aarch64 >= 5.5.
- Loading probes requires root or the capabilities documented in
  `docs/minimum-privileges.md`. Maintained E2E harnesses have stricter root
  requirements.
- macOS and Windows are editing, formatting, and read-only inspection
  environments. Do not run `make`, Go builds/tests, lint, eBPF generation, or
  E2E there.
- Before using a remote Linux builder, verify its OS, architecture, checkout
  path, branch, commit, worktree, submodules, and synchronization state. Never
  assume local edits are present remotely or overwrite remote work.
- New or changed build/test scripts must reject unsupported OS, architecture,
  and kernel combinations before doing eBPF work.
- If the required Linux/root environment is unavailable, report exactly what
  was not run; never claim an unexecuted build or runtime passed.

## Fast mental model

eCapture attaches uprobes, kprobes, and TC programs, reads perf/ring-buffer
events, decodes their binary ABI in Go, and routes validated events to output
handlers and writers.

```text
main.go -> cli.Start() -> Cobra RunE -> runProbe()
  -> config.Validate() -> factory.CreateProbe()
  -> Probe.Initialize() / Start()
  -> embedded eBPF asset + ebpfmanager
  -> perf/ringbuf sample -> EventDecoder.Decode()
  -> events.Dispatcher -> text/keylog/pcap handler -> ByteSink
                       -> typed eCaptureQ EVENT publisher
```

`runProbe` owns signal handling and runtime reload orchestration. A concrete
probe owns its eBPF manager, attachments, maps/decoders, and mode-specific
handlers. `base.BaseProbe` owns shared logging, the default text handler,
readers, dispatch, reorder support, and common shutdown behavior.

See `docs/agent/architecture.md` for the CLI/probe matrix, repository map, and
package ownership.

## Critical cross-file invariants

- CLI imports trigger each probe's `register.go` `init()`. A seemingly unused
  import may be required for factory registration.
- Treat attachment and event plumbing as one atomic change:

  ```text
  C SEC section          <-> manager.Probe.Section
  C BPF function         <-> EbpfFuncName
  target symbol/offset   <-> AttachToFuncName / UAddress
  C map identifier       <-> manager.Map.Name / decoder registration
  C global variable      <-> manager.ConstantEditor
  C event layout         <-> Go event struct / DecodeFromBytes
  ```

- Preserve C/Go event field order, signedness, widths, byte order, arrays, and
  padding. Validate lengths before slicing. Perf samples may contain trailing
  alignment padding, so do not identify variants by exact length alone.
- `Configuration.Validate()` may run more than once and must be idempotent.
- Concrete probes must follow BaseProbe lifecycle ordering. Track every reader;
  custom reader loops must use `TrackReader` and `GoReaderLoop` equivalents so
  shutdown can unblock and join them before closing handlers.
- Dispatcher fan-out is synchronous and unordered. Multiple readers may call
  one handler concurrently; handlers/writers must be concurrency-safe and
  tolerate idempotent close. Perf reorder is per map/reader, not global.
- `--logaddr` is operational logging only. For TLS, GoTLS, and GnuTLS,
  `--eventaddr` is the primary captured-event destination for text, keylog,
  and pcapng. eCaptureQ is an additive typed publisher, not a ByteSink.
- Linux production tags are `linux,netgo,ebpfassets,dynamic`; Android uses
  `ecap_android,netgo,ebpfassets,dynamic`. Preserve CO-RE and non-CO-RE paths.
- Never hand-edit or commit generated `bytecode/*.o`, `bytecode/*.d`,
  `assets/ebpf_probe.go`, `bin/ecapture`, or `coverage.out`. Regenerate
  Protobuf and stringer outputs from their sources.

## Task guides and verification

Before changing a probe, event ABI, build flow, or test harness, read the
corresponding detailed guide listed above. At minimum:

- Documentation-only changes: verify paths, commands, links, and source facts.
- Go logic: format touched files, run targeted tests, and complete full race
  plus production-tag lint gates when Linux is available.
- Event decoders/ABI: add byte-level malformed, short, and padded-sample tests.
- eBPF C or manager setup: clean-build both CO-RE and non-CO-RE variants for
  affected architectures.
- CLI/output/capture modes: run the relevant strict E2E case on a real
  Linux/Android kernel.
- OpenSSL/BoringSSL mappings: test mapping, both asset variants, and the real
  library version.
- CI changes: validate least privilege and trusted/untrusted workflow
  boundaries.

Canonical commands, prerequisites, build races, E2E semantics, and the full
verification matrix live in `docs/agent/build-test.md`.

## Code conventions

- Module/import path: `github.com/gojue/ecapture/v2`; preserve the `/v2`
  suffix in new imports.
- Keep changes focused and follow the nearest working implementation. Probe
  implementations are not perfectly uniform, so do not copy one blindly.
- In probe/domain lifecycle code, prefer structured constructors and codes in
  `internal/errors`, adding context where useful. Preserve normal `%w`
  wrapping at boundaries where that is the local pattern.
- Use `internal/logger` inside probes/runtime code and zerolog in the CLI
  layer. Do not add ad-hoc `fmt.Println` or standard `log` calls for runtime
  logging.
- Format only touched files: `gofmt`/`goimports` for Go and the repository's
  exact clang-format style for C. `make format` is a broad C-only target.
- Keep eBPF verifier limits, bounded loops, stack use, helper availability,
  and old-kernel compatibility in mind.
- Preserve the `github.com/google/gopacket` replacement in `go.mod` unless a
  maintainer explicitly directs otherwise.
- Root `LICENSE` is Apache-2.0. Preserve each file's existing SPDX header;
  some imported or kernel-facing headers use other compatible licenses. Do
  not propagate stale prose that says AGPL, and leave license changes to a
  maintainer-directed task.

## Safety, Git, and release boundaries

- Captured logs, commands, SQL, keylogs, pcap/pcapng files, and test artifacts
  may contain secrets. Never commit or paste them unredacted.
- Preserve unrelated worktree changes. Do not stage, commit, push, open a PR,
  publish, tag, or release unless the user explicitly requests it.
- Name new branches with a conventional purpose prefix such as `feat/`,
  `bugfix/`, `docs/`, `test/`, or `chore/`, followed by a concise kebab-case
  description.
- The default branch is `master`. If asked to commit, follow
  `<package>: <what changed>`, keep the subject <= 70 characters, and explain
  why in the body as documented in `CONTRIBUTING.md`.
- Keep ordinary fork-PR build/test jobs read-only and secret-free. Keep
  scanner-specific write permissions narrowly scoped. Any trusted write-back
  workflow must not execute untrusted fork code or its artifacts.
- Do not weaken security checks, verifier failures, or E2E assertions merely
  to make CI green.

## Known state and traps

- GnuTLS uses versioned C assets selected from the detected library patch
  release; keep the supported version-to-asset table synchronized with
  `kern/gnutls_*_kern.c`.
- Runtime reload reattaches process-lifetime output dependencies and creates a
  fresh probe context, but retains the original factory probe type; it is not
  a cross-probe hot-swap facility.
- Shared CLI fields are copied into module configs manually and unevenly.
  Trace every affected command and `cli/http/` config factory.
- Probe registration currently discards duplicate-registration errors.
- `--btf=0` is called auto, but several paths actually choose non-CO-RE unless
  the value is exactly `1`.
- Do not copy PostgreSQL's current non-CO-RE asset spelling as a template;
  generated objects follow `*_kern_noncore.o`.
- `pkg/event_processor` and `internal/output/encoders` are not in the current
  production CLI event path.
- `make build` is not Go-only. Switching architecture/Android/core variants
  without cleaning can embed stale objects, and parallel `make all -jN` has an
  asset-generation write race.

## Focused references

- Architecture and runtime: `docs/agent/architecture.md`
- Probe and ABI development: `docs/agent/probe-development.md`
- Build and verification: `docs/agent/build-test.md`
- User-facing behavior: `README.md`, `README-zh_Hans.md`
- Build sources: `Makefile`, `variables.mk`, `functions.mk`, `builder/init_env.sh`
- E2E: `test/e2e/README.md`, `test/e2e/QUICK_REFERENCE.md`
- Privileges/security: `docs/minimum-privileges.md`, `SECURITY.md`
- Event forwarding: `docs/event-forward-api.md`, `pkg/ecaptureq/README.md`
- Generated/config docs: `protobuf/README.md`, `protobuf/PROTOCOLS.md`, `docs/remote-config-update-api.md`
- GitHub Copilot PR agent: `.github/agents/pr-agent.agent.md`
