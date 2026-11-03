#!/usr/bin/env bash

# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"

set -euo pipefail

echo "Welcome to eCapture project development environment initialization script."
echo "Home page: https://ecapture.cc"
echo "Github: https://github.com/gojue/ecapture"

if [[ "$(uname -s)" != Linux || ! -r /etc/os-release ]]; then
  echo "Environment initialization requires Ubuntu Linux." >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != ubuntu ]]; then
  echo "Environment initialization requires Ubuntu; found ${PRETTY_NAME:-unknown}." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) host_arch=amd64; minimum_kernel=4.18 ;;
  aarch64|arm64) host_arch=arm64; minimum_kernel=5.5 ;;
  *) echo "Unsupported build host architecture: $(uname -m)" >&2; exit 1 ;;
esac
host_kernel=$(uname -r | cut -d- -f1)
if [[ "$(printf '%s\n%s\n' "$minimum_kernel" "$host_kernel" | sort -V | head -n 1)" != "$minimum_kernel" ]]; then
  echo "Host kernel $host_kernel is too old for $host_arch; require $minimum_kernel or newer." >&2
  exit 1
fi

target_arch=${TARGET_ARCH:-$host_arch}
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
    if [[ "$host_arch" != amd64 || "${VERSION_ID:-}" != 24.04 ]]; then
      echo "Loong64 cross-builds require Ubuntu 24.04 x86_64." >&2
      exit 1
    fi
    cross_packages=(lld-18 llvm-18-tools dwarves qemu-user-static
      libc6-dev-loong64-cross linux-libc-dev-loong64-cross
      libgcc-13-dev-loong64-cross libatomic1-loong64-cross)
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
  clang_suffix=-18
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
"${sudo_cmd[@]}" apt-get -y install build-essential pkgconf libelf-dev \
  "llvm$clang_suffix" "clang$clang_suffix" linux-tools-common linux-tools-generic \
  libssl-dev flex bison bc linux-source git file wget ca-certificates xz-utils \
  "${cross_packages[@]}"

if [[ -n "$clang_suffix" ]]; then
  for tool in clang llc llvm-strip; do
    "${sudo_cmd[@]}" ln -sf "/usr/bin/$tool$clang_suffix" "/usr/local/bin/$tool"
  done
fi
bpftool_bin=$(find /usr/lib -maxdepth 2 -type f -path '/usr/lib/linux-tools-*/bpftool' | sort -V | tail -n 1)
test -x "$bpftool_bin"
"${sudo_cmd[@]}" ln -sf "$bpftool_bin" /usr/local/bin/bpftool
export PATH=/usr/local/bin:$PATH

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
  builder/prepare-loong64-kernel.sh "$kernel_source"
else
  if [[ ! -f "$kernel_source/.config" ]]; then
    make -C "$kernel_source" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" defconfig
  fi
  make -C "$kernel_source" ARCH="$kernel_arch" CROSS_COMPILE="$cross_compile" olddefconfig prepare
fi

echo "The build environment for $target_arch is ready. Run:"
printf 'cd %q\n' "$repo_dir"
printf "export PATH=%q:/usr/local/bin:\$PATH\n" "$(dirname "$(command -v go)")"
printf 'export GOPROXY=%q\n' "${GOPROXY:-https://goproxy.cn}"
printf 'export TARGET_ARCH=%q KERN_HEADERS=%q\n' "$target_arch" "$kernel_source"
if [[ "$target_arch" == loong64 ]]; then
  printf 'export LOONG64_VMLINUX=%q\n' "$kernel_source/vmlinux"
fi
echo 'make clean && make all'
