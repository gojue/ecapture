# E2E implementation status

| Area | Status | Notes |
| --- | --- | --- |
| Shared strict assertions | Complete | Plaintext token, NSS keylog format, pcapng block parser, fatal/decode/loss checks |
| Deterministic local TLS fixture | Complete | TLS 1.2 and TLS 1.3; no external DNS/CA/service dependency |
| Linux OpenSSL `tls` | Covered | `text`, `keylog`, `pcapng`; direct OpenSSL API workload |
| Linux `gotls` | Covered | `text`, `keylog`, `pcapng`; instrumented Go ELF workload |
| Linux `gnutls` test contract | Covered | Strict text, keylog, and pcapng cases are gating |
| Android 13+ BoringSSL `tls` | Covered | `text`, `keylog`, `pcapng`; Conscrypt workload through `app_process` |
| Ubuntu CI matrix | Configured | Ubuntu 22.04 and 24.04 |
| Android CI matrix | Configured | API 33-36 (stable Android 13, 14, 15, and 16) |

The GnuTLS probe loads patch-specific assets and attaches plaintext,
master-secret, and TC programs. Its test contract remains strict and gating;
version mapping changes require validation against the real library release.
