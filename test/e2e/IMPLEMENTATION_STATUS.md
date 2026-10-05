# E2E implementation status

| Area | Status | Notes |
| --- | --- | --- |
| Shared strict assertions | Complete | Plaintext token, NSS keylog format, pcapng block parser, fatal/decode/loss checks |
| Deterministic local TLS fixture | Complete | TLS 1.2 and TLS 1.3; no external DNS/CA/service dependency |
| Linux OpenSSL `tls` | Covered | `text`, `keylog`, `pcapng`; direct OpenSSL API workload |
| Linux `gotls` | Covered | `text`, `keylog`, `pcapng`; instrumented Go ELF workload |
| Linux `gnutls` test contract | Covered | All three strict cases exist; probe implementation remains incomplete |
| Android 13+ BoringSSL `tls` | Covered | `text`, `keylog`, `pcapng`; Conscrypt workload through `app_process` |
| Ubuntu CI matrix | Configured | Ubuntu 22.04 and 24.04 |
| Android CI matrix | Configured | API 33-36 (stable Android 13, 14, 15, and 16) |

The GnuTLS test contract is intentionally not marked passing: the current probe source is a scaffold with no attached event maps. Its tests remain strict; GitHub Actions runs them as a visible non-gating step until the probe is implemented, while direct suite execution returns failure.
