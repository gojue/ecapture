# Security Policy

## Supported Versions

| Version  | Supported          |
|----------|--------------------|
| >= 2.0.x | :white_check_mark: |
| < 2.0.0  | :x:                |

We only provide security patches for the latest minor release. Users on older versions are encouraged to upgrade.

## Reporting a Vulnerability

**Please do NOT file a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in eCapture, please report it responsibly through one of the following channels:

- **Email**: Send a detailed report to [cfc4ncs@gmail.com](mailto:cfc4ncs@gmail.com)
- **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/gojue/ecapture/security/advisories/new)

### What to Include

- A clear description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Potential impact assessment
- (Optional) Suggested fix or patch

### Response Timeline

| Stage | SLA |
|-------|-----|
| Acknowledgment of report | **72 hours** |
| Initial assessment & triage | **7 days** |
| Fix development & testing | **30 days** (may vary by severity) |
| Public disclosure | **90 days** from report (coordinated disclosure) |

We follow a **90-day coordinated disclosure** policy. If a fix is ready before the 90-day window, we will release it as soon as possible and coordinate disclosure timing with the reporter.

### Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Remote code execution, privilege escalation via eCapture | Crafted input causes arbitrary code execution in kernel space |
| **High** | Information disclosure beyond intended scope | eCapture leaks data from unrelated processes |
| **Medium** | Denial of service, resource exhaustion | Crafted input causes excessive memory/CPU usage |
| **Low** | Minor information leakage, documentation issues | Verbose error messages reveal internal paths |

### Scope

The following are considered in-scope for security reports:

- Vulnerabilities in eCapture's Go userspace code
- Vulnerabilities in eCapture's eBPF kernel-space programs
- Supply chain issues (compromised dependencies)
- Misuse vectors that could be mitigated by eCapture itself

The following are **out of scope**:

- General eBPF/kernel security issues (report to kernel security team)
- Vulnerabilities in third-party libraries eCapture hooks (OpenSSL, GnuTLS, etc.)
- Social engineering attacks

## Release Integrity

Starting from v2.0, we provide SHA256 checksums for all release binaries. See [docs/release-verification.md](docs/release-verification.md) for verification instructions.

## Security Considerations for Users

eCapture is a powerful security auditing tool that requires elevated privileges. Please review:

- [docs/minimum-privileges.md](docs/minimum-privileges.md) — Required Linux capabilities and least-privilege configuration
- [docs/defense-detection.md](docs/defense-detection.md) — How to detect and defend against unauthorized use of eCapture

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged in the release notes (unless they prefer anonymity).
