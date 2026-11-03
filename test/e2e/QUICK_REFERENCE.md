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

Android 13+ (rooted/userdebug):

```bash
ANDROID=1 make nocore
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
