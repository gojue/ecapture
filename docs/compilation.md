<!-- MarkdownTOC autolink="true" -->

- [How eCapture works](#how-ecapture-works)
- [eCapture Architecture](#ecapture-architecture)
- [Compilation instructions](#compilation-instructions)
  - [Compiling from source on Linux](#compiling-from-source-on-linux)
  - [compile without BTF](#compile-without-btf)
  - [cross-compilation](#cross-compilation)
  - [Compiling for Windows](#compiling-for-windows)
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

Linux kernel 4.18 or later. x86_64/aarch64 architecture.

**prerequisites**

* golang 1.21 or newer
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

Caution: The following `make` command will install libpcap into the system
directory if `libpcap.a` does not exist under `/usr/local/lib`. If you have
installed libpcap in system without `libpcap.a`, it maybe break your libpcap's
headers.

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

To build an `arm64` artifact on an ubuntu `amd64` system, you can set the `CROSS_ARCH` environment variable to achieve
cross-compilation.

```shell
CROSS_ARCH=arm64 make
```

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

**Prerequisites**: Linux kernel >= 4.18 (x86_64) or >= 5.5 (aarch64), root access, and required tools (see [docs/e2e-tests.md](./docs/e2e-tests.md)).

For detailed information about the test suite, troubleshooting, and CI integration, see [docs/e2e-tests.md](./docs/e2e-tests.md).

## Compiling for Windows

eCapture supports Windows (x86_64 and arm64) using ETW (Event Tracing for Windows) instead of eBPF. The Windows build captures TLS traffic via the Schannel ETW provider and supports DLL function hooking for OpenSSL, MySQL, and PostgreSQL.

### Windows Prerequisites

* **Go 1.21** or newer
* **MinGW-w64** cross-compiler (for CGO, required by Npcap/pcap mode)
  - On Ubuntu: `sudo apt-get install -y gcc-mingw-w64-x86-64`
  - On Windows: install [MSYS2](https://www.msys2.org/) and add `mingw-w64` to PATH
* **Npcap** (optional, for pcap mode): install from [npcap.com](https://npcap.com/) with "WinPcap API-compatible mode" enabled
* **Administrator privileges** required at runtime (ETW sessions need elevation)

### Cross-compiling from Linux

```shell
# Windows amd64
make windows

# Windows arm64
make windows-arm64
```

The `CGO_ENABLED=1` flag is used automatically for Windows targets to support Npcap/pcap mode. If you do not need pcap mode, you can build without CGO by modifying the Makefile.

### Building natively on Windows

```powershell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
$env:CGO_ENABLED = "1"
go build -tags windows -o bin/ecapture.exe main.go
```

### Windows Features

| Feature | Description |
|---------|-------------|
| TLS/Schannel capture | ETW-based capture via Microsoft-Windows-Schannel provider |
| OpenSSL hooking | DLL function hooking for `SSL_read`/`SSL_write` |
| MySQL/PostgreSQL capture | DLL hooking for `mysql_real_query`/`PQexec` |
| pcap mode | Network packet capture via Npcap (requires Npcap installed) |
| keylog mode | TLS key material export in NSS keylog format |

### Windows E2E Tests

PowerShell-based end-to-end tests are located in `test/e2e/windows/`. Run as Administrator:

```powershell
cd test\e2e\windows
.\windows_tls_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_bash_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_mysql_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_postgres_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
```

# What's eBPF

[eBPF](https://ebpf.io)

