#!/usr/bin/env bash
# Pure platform validation shared by the real preflight and its regression tests.

version_at_least() {
    local actual="$1" required="$2"
    [[ "$(printf '%s\n%s\n' "$required" "$actual" | sort -V | head -n 1)" == "$required" ]]
}

check_linux_platform() {
    local os="$1" distribution="$2" release="$3" arch="$4" kernel="$5" uid="$6"
    local minimum_release major minor required_major required_minor
    if [[ "$os" != Linux ]]; then
        log_error "E2E execution requires Linux; current OS is $os"
        return 1
    fi
    case "$distribution" in
        ubuntu) minimum_release=22.04 ;;
        debian) minimum_release=13 ;;
        *)
            log_error "Linux E2E supports Ubuntu 22.04+ or Debian 13+; found $distribution $release"
            return 1
            ;;
    esac
    if [[ ! "$release" =~ ^[0-9]+([.][0-9]+)*$ ]] ||
        ! version_at_least "$release" "$minimum_release"; then
        log_error "Unsupported $distribution release: $release (requires $minimum_release+)"
        return 1
    fi
    if [[ "$uid" != 0 ]]; then
        log_error "E2E tests require root; run with sudo"
        return 1
    fi
    case "$arch" in
        x86_64) required_major=4; required_minor=18 ;;
        aarch64|arm64) required_major=5; required_minor=5 ;;
        loongarch64|loong64) required_major=6; required_minor=6 ;;
        *)
            log_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac
    if [[ ! "$kernel" =~ ^([0-9]+)[.]([0-9]+)([.-]|$) ]]; then
        log_error "Cannot parse kernel version: $kernel"
        return 1
    fi
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    if ((major < required_major || (major == required_major && minor < required_minor))); then
        log_error "Kernel $kernel is too old for $arch (requires $required_major.$required_minor+)"
        return 1
    fi
}
