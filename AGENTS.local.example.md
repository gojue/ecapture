# Local eCapture agent context — example

Copy this file to `AGENTS.local.md` and fill in only machine-local information.
The copy is ignored by Git and is optional; shared repository behavior belongs
in `AGENTS.md`. `AGENTS.local.md` is not a native cross-tool discovery name;
the committed Agent entry points explicitly tell local agents to check it.

## Execution environment

- Local workstation OS: `<macOS | Linux | Windows>`
- Linux builder: SSH alias `<alias from ~/.ssh/config>`
- Remote repository path: `<absolute path on the Linux builder>`
- Default build target: `<native | CROSS_ARCH=arm64 | CROSS_ARCH=amd64>`
- Android target, if any: `<device/emulator description without credentials>`

## Local workflow

- Before using the builder, verify `uname`, architecture, repository path,
  branch, commit, worktree status, and submodules.
- State how local edits reach the builder: `<manual checkout | reviewed rsync |
  shared filesystem | other>`.
- Sync only explicitly intended files. Do not use destructive synchronization
  or overwrite unknown remote changes.
- Run only the repository-supported Linux commands from
  `docs/agent/build-test.md`.
- This file records coordinates and preferences only. It does not authorize an
  agent to connect over SSH, synchronize files, write remotely, or overwrite
  anything; the current user task must authorize those actions.

## Security

- Store SSH destinations behind aliases rather than repeating raw IPs and
  usernames in prompts.
- Do not place passwords, private keys, access tokens, or other credentials in
  this file.
- Do not copy this file's contents into commits, logs, issues, or pull requests.

For automatic Claude Code loading, an optional ignored `CLAUDE.local.md` may
contain only:

```md
@AGENTS.local.md
```
