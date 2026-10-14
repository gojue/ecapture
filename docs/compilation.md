<!-- MarkdownTOC autolink="true" -->

- [How eCapture works](#how-ecapture-works)
- [eCapture Architecture](#ecapture-architecture)
- [Compilation instructions](#compilation-instructions)
  - [Compiling from source on Linux](#compiling-from-source-on-linux)
  - [compile without BTF](#compile-without-btf)
  - [cross-compilation](#cross-compilation)
- [What's eBPF](#whats-ebpf)

<!-- /MarkdownTOC -->
----

# How eCapture works

![](./images/how-ecapture-works.png)

# Architecture

![](./images/ecapture-architecture.png)

# Compilation instructions

## Compiling from source on Linux

### Linux prerequisites

Linux x86_64 requires kernel 4.18+, aarch64 requires 5.5+, and LoongArch64
requires 6.6+. Android supports x86_64 and aarch64 only.

**prerequisites**

* golang 1.26.0 or newer
* clang 9.0 or newer
* cmake 3.18.4 or newer
* clang backend: llvm 9.0 or newer

#### ubuntu

If you are using Ubuntu 20.04 or later versions, you can use a single command to complete the initialization of the
compilation environment.

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```

#### other Linux

In addition to the software listed in the 'Toolchain Version' section above, the following software is also required for
the compilation environment. Please install it yourself.

* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**Clone the repository code and compile it**

The build compiles the pinned libpcap submodule into an architecture-isolated
directory below `.build/`; it does not install or overwrite system libpcap.

```shell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture
```

## compile without BTF

eCapture support BTF disabled with command `make nocore` to compile at 2022/04/17. It can work normally even on Linux
systems that do not support BTF.

```shell
make nocore
bin/ecapture --help
```

## cross-compilation

### Kernel header files

To cross-compile the eCapture tool, you need to install the kernel header files for the target architecture. you need to
install the `linux-source` package.

```shell
sudo apt-get install -y linux-source
cd /usr/src
source_file=$(find . -maxdepth 1 -name "*linux-source*.tar.bz2")
source_dir=$(echo "$source_file" | sed 's/\.tar\.bz2//g')  
sudo tar -xf $source_file
cd $source_dir
test -f .config || yes "" | sudo make oldconfig
```

### ToolChains

To cross-compile binary files for the aarch64 architecture on an amd64 architecture system, you need to install the
gcc-aarch64-linux-gnu toolchain. Similarly, to cross-compile binary files for the amd64 architecture on an aarch64
system, you need to install the gcc-x86-64-linux-gnu toolchain.

* amd64 arch: gcc-aarch64-linux-gnu
* arm64 arch: gcc-x86-64-linux-gnu

### Build Commands

Select the artifact architecture with `TARGET_ARCH=amd64`, `arm64`, or
`loong64`. Without it, the host architecture is used. For example, to build
an `arm64` artifact on an Ubuntu `amd64` system:

```shell
TARGET_ARCH=arm64 make
```

`CROSS_ARCH` remains a compatible alias when `TARGET_ARCH` is unset. If both
are set, `TARGET_ARCH` takes precedence. The `TARGET_MACHINE_ARCH` value
shown by `make env` uses the toolchain spelling (`x86_64`, `aarch64`, or
`loongarch64`).

### Loong64

Loong64 is cross-built only on Ubuntu 24.04 x86_64 with LLVM 18. The public
interface is `TARGET_ARCH=loong64`; Kbuild uses `loongarch`, while Clang and
the sysroot use `loongarch64-linux-gnu`. Do not substitute one spelling for
another.

```shell
builder/prepare-loong64-kernel.sh /path/to/linux-source
make clean TARGET_ARCH=loong64
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  TARGET_ARCH=loong64 make all
```

See [Loong64 build and validation](loong64-support.md) for packages, wrapper
flags, BTF provenance, static PIE verification, and runtime validation limits.

# Testing

eCapture includes comprehensive end-to-end (e2e) tests for the TLS, GnuTLS, and GoTLS modules. These tests verify that eCapture can successfully capture plaintext SSL/TLS traffic on Linux systems.

## Running E2E Tests

Run all e2e tests:
```bash
sudo make e2e
```

Run individual module tests:
```bash
sudo make e2e-tls      # Test OpenSSL/BoringSSL capture
sudo make e2e-gnutls   # Test GnuTLS capture
sudo make e2e-gotls    # Test Go TLS capture
```

**Prerequisites**: Linux kernel >= 4.18 (x86_64) or >= 5.5 (aarch64), root
access, and required tools (see [docs/e2e-tests.md](./docs/e2e-tests.md)).

For detailed information about the test suite, troubleshooting, and CI integration, see [docs/e2e-tests.md](./docs/e2e-tests.md).

# What's eBPF

[eBPF](https://ebpf.io)
