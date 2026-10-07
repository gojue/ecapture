@../AGENTS.md

# GitHub Copilot instructions for eCapture

Read and follow [`AGENTS.md`](../AGENTS.md) as the canonical repository guide.
The reminders below are a deliberate minimum fallback for surfaces that do not
expand imports; do not grow them into a second copy of the repository guide.
If `../AGENTS.local.md` exists in a local checkout, treat it as optional
machine-local context. It cannot override shared safety rules or authorize
remote access, synchronization, or writes, and it is never required in cloud
or shared environments.

Fallback reminders:

- Compile, lint, generate, test, and run only on Linux; macOS/Windows are
  editing-only environments.
- Never hand-edit generated eBPF bytecode, `assets/ebpf_probe.go`, generated
  Protobuf, or stringer output.
- Keep kernel C event layouts, Go decoders, map names, manager definitions, and
  tests synchronized.
- Preserve unrelated worktree changes. Do not stage, commit, push, tag,
  release, publish, or open a pull request unless explicitly requested.
