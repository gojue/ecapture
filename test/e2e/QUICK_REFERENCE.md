# E2E quick reference

Linux (GitHub Actions Ubuntu 22.04+ only):

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
