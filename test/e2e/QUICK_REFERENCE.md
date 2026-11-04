# E2E quick reference

Linux (Ubuntu 22.04+ or Debian 13+; x86_64, aarch64/arm64, or LoongArch64):

```bash
make all
sudo make e2e-linux

sudo make e2e-tls
sudo make e2e-gotls
sudo make e2e-gnutls
sudo make e2e-advanced

sudo E2E_MODULES=tls E2E_MODES=text bash test/e2e/run_e2e.sh
sudo E2E_MODULES='tls gotls gnutls' E2E_MODES='keylog pcapng' bash test/e2e/run_e2e.sh
```

LoongArch requires kernel >= 6.6. To run an existing verified artifact, set
`ECAPTURE_BINARY=/absolute/path/to/ecapture`; see [Linux setup](README.md#linux).

Separate non-TLS and CLI suites (same Linux/root requirements):

```bash
sudo make e2e-bash
sudo make e2e-zsh
sudo make e2e-mysql
sudo make e2e-bash-advanced
sudo make e2e-mysql-advanced
sudo make e2e-postgres
sudo make e2e-edge-cases

sudo E2E_NON_TLS_MODULES='bash mysqld' E2E_NON_TLS_ADVANCED=1 \
  bash test/e2e/linux/common_config_test.sh
```

MySQL uses a local capture fixture. PostgreSQL requires an existing local
database and performs only read-only SELECTs over a Unix socket. Advanced
non-TLS cases default to off. The opt-in `E2E_BASH_ERRNO=1` reproduces a known
production bug and is expected to fail until fixed. See
[prerequisites and scope](README.md#non-tls-and-cli-checks).
`make e2e-ecaptureq` runs the maintained Linux TLS matrix with typed receiver
assertions; `make e2e-advanced` adds TLS stress only.

Android 13+ (rooted/userdebug):

```bash
make clean
ANDROID=1 TARGET_ARCH=arm64 make nocore
bash test/e2e/android/build_boringssl_client.sh 33
make setup-android-env
make e2e-android-all
```

Keep successful artifacts:

```bash
sudo E2E_KEEP_ARTIFACTS=1 E2E_ARTIFACT_ROOT=/tmp/ecapture-results make e2e-linux
E2E_KEEP_ARTIFACTS=1 E2E_ARTIFACT_ROOT=/tmp/ecapture-android-results make e2e-android-all
```

See [README.md](README.md) for the coverage matrix, prerequisites, and assertions.
