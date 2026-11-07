#!/usr/bin/env bash

# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"

set -euo pipefail

echo "Welcome to eCapture project development environment initialization script."
echo "Home page: https://ecapture.cc"
echo "Github: https://github.com/gojue/ecapture"

if [[ "$(uname -s)" != Linux || ! -r /etc/os-release ]]; then
  echo "Environment initialization requires supported Ubuntu or Debian Linux." >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != ubuntu && "${ID:-}" != debian ]]; then
  echo "Environment initialization requires Ubuntu or Debian; found ${PRETTY_NAME:-unknown}." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) host_arch=amd64; minimum_kernel=4.18 ;;
  aarch64|arm64) host_arch=arm64; minimum_kernel=5.5 ;;
  loongarch64|loong64) host_arch=loong64; minimum_kernel=6.6 ;;
  *) echo "Unsupported build host architecture: $(uname -m)" >&2; exit 1 ;;
esac
host_kernel=$(uname -r | cut -d- -f1)
if [[ "$(printf '%s\n%s\n' "$minimum_kernel" "$host_kernel" | sort -V | head -n 1)" != "$minimum_kernel" ]]; then
  echo "Host kernel $host_kernel is too old for $host_arch; require $minimum_kernel or newer." >&2
  exit 1
fi

target_arch=${TARGET_ARCH-${CROSS_ARCH-$host_arch}}
target_arch=${target_arch:-$host_arch}
if [[ "$ID" == debian ]]; then
  if [[ "$host_arch" != loong64 || "$target_arch" != loong64 ||
        ! "${VERSION_ID:-}" =~ ^[0-9]+([.][0-9]+)*$ ]] ||
      [[ "$(printf '%s\n%s\n' 13 "${VERSION_ID:-0}" | sort -V | head -n 1)" != 13 ]]; then
    echo 'Debian initialization supports native LoongArch64 on Debian 13+ only.' >&2
    exit 1
  fi
elif [[ "$host_arch" == loong64 ]]; then
  echo 'Native LoongArch64 initialization requires Debian 13+.' >&2
  exit 1
fi
cross_compile=
cross_packages=()
case "$target_arch" in
  amd64)
    kernel_arch=x86
    if [[ "$host_arch" != amd64 ]]; then
      cross_compile=x86_64-linux-gnu-
      cross_packages=(gcc-x86-64-linux-gnu libc6-dev-amd64-cross)
    fi
    ;;
  arm64)
    kernel_arch=arm64
    if [[ "$host_arch" != arm64 ]]; then
      cross_compile=aarch64-linux-gnu-
      cross_packages=(gcc-aarch64-linux-gnu libc6-dev-arm64-cross)
    fi
    ;;
  loong64)
    if [[ "$host_arch" == loong64 ]]; then
      cross_packages=(dwarves)
    elif [[ "$host_arch" == amd64 && "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]; then
      cross_packages=(dwarves qemu-user-static
        libc6-dev-loong64-cross linux-libc-dev-loong64-cross
        libgcc-13-dev-loong64-cross libatomic1-loong64-cross)
    else
      echo "Loong64 cross-builds require Ubuntu 24.04 x86_64." >&2
      exit 1
    fi
    ;;
  *) echo "Unsupported TARGET_ARCH: $target_arch; use amd64, arm64, or loong64." >&2; exit 1 ;;
esac
if [[ "$target_arch" == loong64 && "${ANDROID:-0}" != 0 ]]; then
  echo "Android/loong64 is not supported." >&2
  exit 1
fi

case "${VERSION_ID:-}" in
  20.04|20.10) clang_suffix=-10 ;;
  21.04) clang_suffix=-11 ;;
  21.10|22.10) clang_suffix=-12 ;;
  22.04|24.04) clang_suffix=-14 ;;
  23.04|23.10) clang_suffix=-15 ;;
  *) clang_suffix= ;;
esac
if [[ "$target_arch" == loong64 ]]; then
  clang_suffix=-22
fi

# Reuse the checkout containing this script, including its current branch.
# The curl/bash bootstrap has no script path and uses ~/ecapture instead.
repo_dir="$HOME/ecapture"
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  if [[ -f "$script_root/go.mod" && -f "$script_root/variables.mk" ]]; then
    repo_dir=$script_root
  fi
fi
if [[ -e "$repo_dir" && ( ! -f "$repo_dir/go.mod" || ! -f "$repo_dir/variables.mk" ) ]]; then
  echo "Checkout destination already exists and is not an eCapture checkout: $repo_dir" >&2
  exit 1
fi

sudo_cmd=()
if [[ "$EUID" != 0 ]]; then
  sudo_cmd=(sudo)
fi
"${sudo_cmd[@]}" apt-get update
if [[ "$target_arch" == loong64 && "$host_arch" == amd64 ]]; then
  # Ubuntu 24.04 needs the versioned LLVM repository; do not execute llvm.sh.
  "${sudo_cmd[@]}" apt-get -y install ca-certificates wget gnupg
  if [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] &&
      ! getent ahostsv4 apt.llvm.org >/dev/null; then
    # Keep this DNS workaround on disposable hosted runners, never developer hosts.
    # HTTPS and the pinned repository signature still authenticate all downloads.
    echo 'System DNS cannot resolve apt.llvm.org; trying Google DNS over HTTPS.'
    "${sudo_cmd[@]}" apt-get -y install curl python3
    llvm_hosts=$(curl --fail --silent --show-error --retry 3 \
      --connect-timeout 10 --max-time 30 \
      'https://dns.google/resolve?name=apt.llvm.org&type=A' |
      python3 -c '
import ipaddress
import json
import sys

response = json.load(sys.stdin)
if response.get("Status") != 0 or response.get("TC"):
    sys.exit("LLVM DNS fallback returned an unsuccessful or truncated response")
addresses = {ipaddress.IPv4Address(record["data"])
             for record in response.get("Answer", []) if record.get("type") == 1}
if not addresses or any(not address.is_global or address.is_multicast for address in addresses):
    sys.exit("LLVM DNS fallback did not return public IPv4 addresses")
for address in sorted(addresses):
    print(f"{address} apt.llvm.org")
')
    printf '%s\n' "$llvm_hosts" | "${sudo_cmd[@]}" tee -a /etc/hosts >/dev/null
  fi
  llvm_key=$(mktemp "${TMPDIR:-/tmp}/ecapture-llvm-key.XXXXXX.asc")
  trap 'rm -f -- "$llvm_key" "$llvm_key.gpg"' EXIT
  echo 'Downloading the LLVM repository signing key (up to 5 attempts).'
  wget --timeout=30 --tries=5 --waitretry=2 \
    --retry-connrefused --retry-on-host-error \
    --retry-on-http-error=429,500,502,503,504 \
    -O "$llvm_key" https://apt.llvm.org/llvm-snapshot.gpg.key
  key_fingerprint=$(gpg --batch --show-keys --with-colons "$llvm_key" | awk -F: '$1 == "fpr" {print $10; exit}')
  if [[ "$key_fingerprint" != 6084F3CF814B57C1CF12EFD515CF4D18AF4F7421 ]]; then
    echo 'Unexpected LLVM repository signing key' >&2
    exit 1
  fi
  gpg --batch --yes --dearmor --output "$llvm_key.gpg" "$llvm_key"
  "${sudo_cmd[@]}" install -m 0644 "$llvm_key.gpg" /usr/share/keyrings/ecapture-llvm.gpg
  printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/ecapture-llvm.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-22 main' |
    "${sudo_cmd[@]}" tee /etc/apt/sources.list.d/ecapture-llvm22.list >/dev/null
  rm -f -- "$llvm_key" "$llvm_key.gpg"
  trap - EXIT
  "${sudo_cmd[@]}" apt-get update
fi
compiler_packages=("llvm$clang_suffix" "clang$clang_suffix")
if [[ "$target_arch" == loong64 ]]; then
  compiler_packages=()
  for package in llvm-22 clang-22 lld-22 llvm-22-tools; do
    package_version=$(apt-cache madison "$package" | awk '$3 ~ /^(1:)?22[.]1[.]8[-+~]/ {print $3; exit}')
    if [[ -z "$package_version" ]]; then
      echo "Required $package 22.1.8 is unavailable from configured package sources" >&2
      exit 1
    fi
    compiler_packages+=("$package=$package_version")
  done
fi
bpf_packages=(linux-tools-common linux-tools-generic)
if [[ "$ID" == debian ]]; then
  bpf_packages=(bpftool)
fi
"${sudo_cmd[@]}" apt-get -y install build-essential pkgconf libelf-dev \
  "${compiler_packages[@]}" "${bpf_packages[@]}" \
  libssl-dev flex bison bc linux-source git file wget ca-certificates xz-utils \
  "${cross_packages[@]}"

if [[ -n "$clang_suffix" ]]; then
  for tool in clang llc llvm-strip; do
    "${sudo_cmd[@]}" ln -sf "/usr/bin/$tool$clang_suffix" "/usr/local/bin/$tool"
  done
fi
if [[ "$ID" == ubuntu ]]; then
  bpftool_bin=$(find /usr/lib -maxdepth 2 -type f -path '/usr/lib/linux-tools-*/bpftool' | sort -V | tail -n 1)
  test -x "$bpftool_bin"
  "${sudo_cmd[@]}" ln -sf "$bpftool_bin" /usr/local/bin/bpftool
fi
export PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:$PATH

go_version=$(go version 2>/dev/null | awk '{sub(/^go/, "", $3); print $3}' || true)
if [[ -z "$go_version" || "$(printf '%s\n%s\n' 1.26.0 "$go_version" | sort -V | head -n 1)" != 1.26.0 ]]; then
  go_archive=$(mktemp "${TMPDIR:-/tmp}/ecapture-go.XXXXXX.tar.gz")
  trap 'rm -f -- "$go_archive"' EXIT
  wget -O "$go_archive" "https://golang.google.cn/dl/go1.26.0.linux-$host_arch.tar.gz"
  tar -tzf "$go_archive" >/dev/null
  "${sudo_cmd[@]}" rm -rf /usr/local/go
  "${sudo_cmd[@]}" tar -C /usr/local -xzf "$go_archive"
  export PATH=/usr/local/go/bin:$PATH
  rm -f -- "$go_archive"
  trap - EXIT
fi

if [[ ! -d "$repo_dir" ]]; then
  git clone --recurse-submodules https://github.com/gojue/ecapture.git "$repo_dir"
fi
cd "$repo_dir"
git submodule update --init --recursive
builder/check-build-environment.sh "$target_arch" linux

source_file=$(find /usr/src -maxdepth 1 -name 'linux-source*.tar.*' | sort -V | tail -n 1)
test -f "$source_file"
source_name=$(basename "$source_file")
kernel_parent="$repo_dir/.build/kernel-$target_arch"
kernel_source="$kernel_parent/${source_name%%.tar.*}"
mkdir -p "$kernel_parent"
if [[ ! -f "$kernel_source/Makefile" ]]; then
  tar -xf "$source_file" -C "$kernel_parent"
fi
if [[ "$target_arch" == loong64 ]]; then
  if [[ "$host_arch" == loong64 && -r /sys/kernel/btf/vmlinux ]]; then
    # Native CO-RE uses this host's BTF; non-CO-RE still needs prepared headers.
    if [[ ! -f "$kernel_source/.config" ]]; then
      make -C "$kernel_source" ARCH=loongarch LLVM="$clang_suffix" defconfig
    fi
    make -C "$kernel_source" ARCH=loongarch LLVM="$clang_suffix" olddefconfig prepare
    loong64_vmlinux=/sys/kernel/btf/vmlinux
  else
    builder/prepare-loong64-kernel.sh "$kernel_source"
    loong64_vmlinux="$kernel_source/vmlinux"
  fi
else
  if [[ ! -f "$kernel_source/.config" ]]; then
    make -C "$kernel_source" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" defconfig
  fi
  make -C "$kernel_source" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" olddefconfig prepare
fi

echo "The build environment for $target_arch is ready. Run:"
printf 'cd %q\n' "$repo_dir"
printf "export PATH=%q:/usr/local/bin:/usr/sbin:\$PATH\n" "$(dirname "$(command -v go)")"
printf 'export GOPROXY=%q\n' "${GOPROXY:-https://proxy.golang.org,direct}"
printf 'export TARGET_ARCH=%q KERN_HEADERS=%q\n' "$target_arch" "$kernel_source"
if [[ "$target_arch" == loong64 ]]; then
  printf 'export LOONG64_VMLINUX=%q\n' "$loong64_vmlinux"
fi
echo 'make clean && make all'
