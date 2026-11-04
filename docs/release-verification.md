# Release Verification Guide

Verify a downloaded package before extracting or running it. The current
[publishing recipe](../builder/Makefile.release) generates
`checksum-<release-tag>.txt`, with SHA256 checksums for the release packages.
For older releases, use the checksum asset actually listed on that release.

## Download and verify

On Linux, set the tag and architecture to the release you selected:

```bash
RELEASE_VERSION="v2.9.1"
RELEASE_ARCH="amd64"
RELEASE_BASE="https://github.com/gojue/ecapture/releases/download/${RELEASE_VERSION}"
RELEASE_ARCHIVE="ecapture-${RELEASE_VERSION}-linux-${RELEASE_ARCH}.tar.gz"

wget "${RELEASE_BASE}/${RELEASE_ARCHIVE}"
wget "${RELEASE_BASE}/checksum-${RELEASE_VERSION}.txt"
sha256sum --check --ignore-missing "checksum-${RELEASE_VERSION}.txt"
```

The command must succeed and print `OK` for the archive you downloaded, for
example:

```text
ecapture-v2.9.1-linux-amd64.tar.gz: OK
```

`--ignore-missing` skips packages for other architectures that you did not
download. To inspect one checksum manually:

```bash
sha256sum "${RELEASE_ARCHIVE}"
grep -F -- "${RELEASE_ARCHIVE}" "checksum-${RELEASE_VERSION}.txt"
```

Compare the full SHA256 value. A checksum checks integrity against the
published manifest; it is not a digital signature. The current publishing
workflow does not generate cosign signatures or artifact attestations.

## Docker image digests

After pulling a versioned image, inspect its digest:

```bash
docker pull "gojue/ecapture:${RELEASE_VERSION}"
docker inspect --format='{{index .RepoDigests 0}}' "gojue/ecapture:${RELEASE_VERSION}"
```

The result has the form `gojue/ecapture@sha256:<digest>`. Use that digest as
the image reference in deployment configuration to pin the image contents.
See the [minimum privileges guide](minimum-privileges.md) for runtime flags.

## Reporting integrity issues

If a checksum differs, do not run the downloaded package. Report suspected
tampering through the [security reporting process](../SECURITY.md#reporting-a-vulnerability).
