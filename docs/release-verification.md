# Release Verification Guide

This document describes how to verify the integrity of eCapture release artifacts.

## SHA256 Checksum Verification

Every eCapture release includes a `SHA256SUMS` file containing checksums for all release binaries.

### Download and Verify

```bash
# 1. Download the release binary and checksum file
RELEASE_VERSION="v2.0.1"
wget https://github.com/gojue/ecapture/releases/download/${RELEASE_VERSION}/ecapture-${RELEASE_VERSION}-linux-amd64.tar.gz
wget https://github.com/gojue/ecapture/releases/download/${RELEASE_VERSION}/SHA256SUMS

# 2. Verify the checksum
sha256sum -c SHA256SUMS --ignore-missing
```

Expected output:
```
ecapture-v2.0.1-linux-amd64.tar.gz: OK
```

### Manual Verification

```bash
# Compute checksum of the downloaded file
sha256sum ecapture-${RELEASE_VERSION}-linux-amd64.tar.gz

# Compare with the value in SHA256SUMS
grep "ecapture-${RELEASE_VERSION}-linux-amd64.tar.gz" SHA256SUMS
```

## Docker Image Verification

### Verify Image Digest

```bash
# Pull with digest verification
docker pull gojue/ecapture:latest

# Check the image digest
docker inspect --format='{{index .RepoDigests 0}}' gojue/ecapture:latest
```

### Pin to Specific Digest

For production environments, pin the Docker image to a specific digest instead of a mutable tag:

```bash
# Get the digest
docker inspect --format='{{index .RepoDigests 0}}' gojue/ecapture:latest
# Output: gojue/ecapture@sha256:<digest>

# Use the digest in your deployment
docker run --rm --privileged=true --net=host gojue/ecapture@sha256:<digest> tls
```

## Planned: Cosign Signature Verification

> **Status: Planned for a future release**

We are working on adopting [Sigstore cosign](https://github.com/sigstore/cosign) for cryptographic signing of release artifacts. Once implemented, you will be able to verify releases as follows:

```bash
# Future: Verify with cosign
cosign verify-blob \
  --signature ecapture-${RELEASE_VERSION}-linux-amd64.tar.gz.sig \
  --certificate ecapture-${RELEASE_VERSION}-linux-amd64.tar.gz.cert \
  ecapture-${RELEASE_VERSION}-linux-amd64.tar.gz
```

## Planned: GitHub Actions Artifact Attestations

> **Status: Planned for a future release**

We plan to leverage [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) to provide SLSA provenance for all release builds. This will allow verification that artifacts were built in our CI/CD pipeline.

## Reporting Integrity Issues

If you find a checksum mismatch or suspect that a release has been tampered with, please immediately report it via our [security vulnerability reporting process](../SECURITY.md#reporting-a-vulnerability).

