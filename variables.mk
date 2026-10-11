CMD_MAKE = make
CMD_LLC ?= llc
CMD_TR ?= tr
CMD_CUT ?= cut
CMD_AWK ?= awk
CMD_SED ?= sed
CMD_FILE ?= file
CMD_GIT ?= git
CMD_CLANG ?= clang
CMD_CC ?= gcc
CMD_CXX ?= g++
CMD_CC_PREFIX ?=
CMD_AR ?= ar
CMD_AR_PREFIX ?=
CMD_RANLIB ?= ranlib
CMD_NM ?= nm
CMD_STRIP ?= llvm-strip
CMD_OBJCOPY ?= objcopy
CMD_OBJDUMP ?= objdump
CMD_READELF ?= readelf
CMD_LD_LLD ?= ld.lld
CMD_RM ?= rm
CMD_INSTALL ?= install
CMD_MKDIR ?= mkdir
CMD_TOUCH ?= touch
CMD_PKGCONFIG ?= pkg-config
CMD_GO ?= go
CMD_GREP ?= grep
CMD_CAT ?= cat
CMD_MD5 ?= md5sum
CMD_BPFTOOL ?= bpftool
CMD_TAR ?= tar
CMD_RPM_SETUP_TREE ?= rpmdev-setuptree
CMD_RPMBUILD ?= rpmbuild
CMD_CHECKSUM ?= sha256sum
CMD_GITHUB ?= gh
CMD_MV ?= mv
CMD_CP ?= cp
CMD_CD ?= cd
CMD_DPKG-DEB ?= dpkg-deb
CMD_ECHO ?= echo

BYTECODE_FILES ?= all
STYLE    ?= "{BasedOnStyle: Google, IndentWidth: 4, TabWidth: 4, UseTab: Never, ColumnLimit: 120, AlignAfterOpenBracket: DontAlign, BinPackArguments: true, BreakStringLiterals: false}"
IGNORE_LESS52 ?=
AUTOGENCMD ?=
BPFHEADER := -I ./kern
SUDO ?=
LIBPCAP_ARCH ?=
GOARCH ?=
DEBUG_PRINT ?=
# GCC remains the default libpcap/cgo compiler for the established amd64 and
# arm64 release paths. Loong64 overrides the complete C/link toolchain below.
CGO_ENABLED = 1
TARGET_TAG ?= linux
KERNEL_HEADER_GEN ?= whoami
HOST_OS ?= $(shell uname -s)
HOST_ARCH ?= $(shell uname -m)
UNAME_R := $(shell uname -r)
HOST_VERSION_SHORT := $(shell uname -r | cut -d'-' -f 1)

ifeq ($(HOST_ARCH),x86_64)
	NATIVE_GOARCH := amd64
else ifneq ($(filter $(HOST_ARCH),aarch64 arm64),)
	NATIVE_GOARCH := arm64
else ifneq ($(filter $(HOST_ARCH),loongarch64 loong64),)
	NATIVE_GOARCH := loong64
else
	NATIVE_GOARCH := unsupported
endif

TARGET_GOARCH := $(if $(strip $(CROSS_ARCH)),$(strip $(CROSS_ARCH)),$(NATIVE_GOARCH))
ifeq ($(filter $(TARGET_GOARCH),amd64 arm64 loong64),)
	$(error unsupported target architecture "$(TARGET_GOARCH)"; use amd64, arm64, or loong64)
endif

ifeq ($(TARGET_GOARCH),amd64)
	TARGET_ARCH := x86_64
	LINUX_ARCH := x86
	GOARCH := amd64
	LIBPCAP_ARCH := x86_64-pc-linux-gnu
	BPF_TARGET_TRIPLE := x86_64
else ifeq ($(TARGET_GOARCH),arm64)
	TARGET_ARCH := aarch64
	LINUX_ARCH := arm64
	GOARCH := arm64
	LIBPCAP_ARCH := aarch64-unknown-linux-gnu
	BPF_TARGET_TRIPLE := aarch64
	# bpf_probe_read_user arrived after the pre-5.2 compatibility asset.
	IGNORE_LESS52 := -ignore '.*_less52\.o'
else ifeq ($(TARGET_GOARCH),loong64)
	LOONG64_SYSROOT ?= /
	LOONG64_TARGET_ROOT ?= /usr/loongarch64-linux-gnu
	LOONG64_GCC_RUNTIME_DIR ?= /usr/lib/gcc-cross/loongarch64-linux-gnu/13
	LOONG64_VMLINUX ?=
	TARGET_ARCH := loongarch64
	LINUX_ARCH := loongarch
	GOARCH := loong64
	LIBPCAP_ARCH := loongarch64-unknown-linux-gnu
	BPF_TARGET_TRIPLE := loongarch64-linux-gnu
	TARGET_C_ABI_FLAGS := -mabi=lp64d
	IGNORE_LESS52 := -ignore '.*_less52\.o'
	override CMD_CLANG := clang-18
	override CMD_LLC := llc-18
	override CMD_CC := $(CURDIR)/builder/loong64-clang
	override CMD_CXX := $(CURDIR)/builder/loong64-clang++
	override CMD_AR := llvm-ar-18
	override CMD_RANLIB := llvm-ranlib-18
	override CMD_NM := llvm-nm-18
	override CMD_STRIP := llvm-strip-18
	override CMD_OBJCOPY := llvm-objcopy-18
	override CMD_OBJDUMP := llvm-objdump-18
	override CMD_READELF := llvm-readelf-18
	override CMD_LD_LLD := ld.lld-18
	LOONG64_RUNTIME_FLAGS := --rtlib=libgcc -L$(LOONG64_GCC_RUNTIME_DIR)
	LIBPCAP_LDFLAGS := -fuse-ld=lld $(LOONG64_RUNTIME_FLAGS)
	GO_EXTLDFLAGS := -static -static-pie -fuse-ld=lld $(LOONG64_RUNTIME_FLAGS)
	CGO_LINK_FLAGS := $(LIBPCAP_LDFLAGS)
	export LOONG64_SYSROOT LOONG64_TARGET_ROOT LOONG64_GCC_RUNTIME_DIR
endif

ifeq ($(CGO_LINK_FLAGS),)
	CGO_LINK_FLAGS := -static
endif
ifeq ($(GO_EXTLDFLAGS),)
	GO_EXTLDFLAGS := -static
endif

ifneq ($(TARGET_GOARCH),$(NATIVE_GOARCH))
	ifeq ($(TARGET_GOARCH),amd64)
		CMD_CC_PREFIX := x86_64-linux-gnu-
		CMD_AR_PREFIX := x86_64-linux-gnu-
	else ifeq ($(TARGET_GOARCH),arm64)
		CMD_CC_PREFIX := aarch64-linux-gnu-
		CMD_AR_PREFIX := aarch64-linux-gnu-
	endif
endif

ifndef DEBUG
	DEBUG = 0
endif

ifeq ($(DEBUG),1)
	DEBUG_PRINT := -DDEBUG_PRINT
endif

TARGET_OS ?= linux
ifndef ANDROID
	ANDROID = 0
endif

ifeq ($(ANDROID),1)
	TARGET_TAG := ecap_android
	TARGET_OS = android
endif

ifeq ($(TARGET_GOARCH),loong64)
	ifeq ($(ANDROID),1)
		$(error Android/loong64 is not supported; Loong64 is a Linux-only target)
	endif
endif

ARCH_BUILD_DIR := .build/$(TARGET_TAG)-$(GOARCH)
BYTECODE_DIR := $(ARCH_BUILD_DIR)/bytecode
LIBPCAP_BUILD_DIR := $(ARCH_BUILD_DIR)/libpcap
TARGET_LIBPCAP := $(LIBPCAP_BUILD_DIR)/libpcap.a
GENERATED_ASSET := assets/ebpf_probe_$(TARGET_TAG)_$(GOARCH)_bindata.go
LEGACY_GENERATED_ASSET := assets/ebpf_probe_$(TARGET_TAG)_$(GOARCH).go
OUT_BIN := $(ARCH_BUILD_DIR)/bin/ecapture
COMPAT_OUT_BIN := bin/ecapture

ifeq ($(TARGET_TAG),ecap_android)
	ASSET_BUILD_TAG := ebpfassets \&\& $(GOARCH) \&\& ecap_android
else
	ASSET_BUILD_TAG := ebpfassets \&\& $(GOARCH) \&\& !ecap_android
endif

#
# tools version
#
CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell $(CMD_ECHO) $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell $(CMD_ECHO) $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)

# tags date info
TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")
LAST_GIT_TAG := $(TAG)-$(DATE)-$(COMMIT)
RPM_RELEASE := $(DATE).$(COMMIT)

#VERSION_NUM ?= $(if $(SNAPSHOT_VERSION),$(SNAPSHOT_VERSION),$(LAST_GIT_TAG))
DEB_VERSION ?=
ifndef SNAPSHOT_VERSION
	VERSION_NUM = $(LAST_GIT_TAG)
	DEB_VERSION = v0.0.0
else
	VERSION_NUM = $(SNAPSHOT_VERSION)
	DEB_VERSION = $(SNAPSHOT_VERSION)
endif

#
# environment
#
#SNAPSHOT_VERSION ?= $(shell git rev-parse HEAD)
BUILD_DATE := $(shell date +%Y-%m-%d)

LINUX_SOURCE_FILE := $(shell find /usr/src -maxdepth 1 -name "*linux-source*.tar.bz2")
LINUX_SOURCE_PATH := $(shell echo $(LINUX_SOURCE_FILE) | $(CMD_SED) 's/\.tar\.bz2//g')

# Determine whether the command sudo exists
# on docerk or the arm64 docker simulated by qemu, the sudo command does not exist
ifeq ($(shell command -v sudo 2> /dev/null),)
	SUDO =
else
	SUDO = sudo
endif

ifeq ($(TARGET_GOARCH),loong64)
	BPFHEADER += -I ./kern/bpf/loongarch
	AUTOGENCMD = ./builder/generate-loong64-vmlinux-header.sh "$(KERN_SRC_PATH)" "$(LOONG64_VMLINUX)" "kern/bpf/loongarch/vmlinux.h"
else ifeq ($(TARGET_GOARCH),arm64)
	BPFHEADER += -I ./kern/bpf/arm64
	AUTOGENCMD = test -f kern/bpf/arm64/vmlinux.h
else
	BPFHEADER += -I ./kern/bpf/x86
	AUTOGENCMD = test -f kern/bpf/x86/vmlinux.h || $(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/bpf/x86/vmlinux.h
endif

#
# include vpath
#
ifdef CROSS_ARCH
	ifeq ($(TARGET_GOARCH),loong64)
		KERNEL_HEADER_GEN = $(MAKE) ARCH=loongarch LLVM=-18 prepare V=0
	else
		KERNEL_HEADER_GEN = yes "" | $(SUDO) make ARCH=$(LINUX_ARCH) CROSS_COMPILE=$(CMD_CC_PREFIX) prepare V=0
	endif
	ifdef KERN_HEADERS
		LINUX_SOURCE_PATH = $(KERN_HEADERS)
	else
		KERN_HEADERS = $(LINUX_SOURCE_PATH)
    endif
endif

KERN_RELEASE ?= $(UNAME_R)
KERN_BUILD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BUILD_PATH)))

BPF_NOCORE_TAG = $(subst .,_,$(KERN_RELEASE)):$(subst .,_,$(VERSION_NUM))

#
# BPF Source file
#
TARGETS := kern/boringssl_na
TARGETS += kern/boringssl_a_13
TARGETS += kern/boringssl_a_14
TARGETS += kern/boringssl_a_15
TARGETS += kern/boringssl_a_16
TARGETS += kern/boringssl_a_17
TARGETS += kern/openssl_1_1_1a
TARGETS += kern/openssl_1_1_1b
TARGETS += kern/openssl_1_1_1d
TARGETS += kern/openssl_1_1_1j
TARGETS += kern/openssl_1_1_0a
TARGETS += kern/openssl_1_0_2a
TARGETS += kern/openssl_3_0_0
TARGETS += kern/openssl_3_0_12
TARGETS += kern/openssl_3_1_0
TARGETS += kern/openssl_3_2_0
TARGETS += kern/openssl_3_2_3
TARGETS += kern/openssl_3_2_4
TARGETS += kern/openssl_3_3_0
TARGETS += kern/openssl_3_3_2
TARGETS += kern/openssl_3_3_3
TARGETS += kern/openssl_3_4_0
TARGETS += kern/openssl_3_4_1
TARGETS += kern/openssl_3_5_0
TARGETS += kern/gotls
TARGETS += kern/bash

ifeq ($(ANDROID),0)
	TARGETS += kern/zsh
	TARGETS += kern/gnutls_3_6_12
	TARGETS += kern/gnutls_3_6_13
	TARGETS += kern/gnutls_3_7_0
	TARGETS += kern/gnutls_3_7_3
	TARGETS += kern/gnutls_3_7_7
	TARGETS += kern/gnutls_3_8_4
	TARGETS += kern/gnutls_3_8_7
	TARGETS += kern/nspr
	TARGETS += kern/mysqld
	TARGETS += kern/postgres
endif


# Generate file name-scheme based on TARGETS
KERN_SOURCES := ${TARGETS:=_kern.c}
KERN_BASENAMES := $(notdir $(basename $(KERN_SOURCES)))
KERN_OBJECTS := $(addprefix $(BYTECODE_DIR)/,$(addsuffix _core.o,$(KERN_BASENAMES)))
KERN_OBJECTS_NOCORE := $(addprefix $(BYTECODE_DIR)/,$(addsuffix _noncore.o,$(KERN_BASENAMES)))


EXTRA_CFLAGS ?= -O2 -mcpu=v1 \
	$(DEBUG_PRINT)	\
	-nostdinc \
	-Wno-pointer-sign

CLANG_SYSTEM_INCLUDE = $(shell $(CMD_CLANG) -print-file-name=include)
EXTRA_CFLAGS_NOCORE ?= -emit-llvm -O2 -S\
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	-xc -g -isystem $(CLANG_SYSTEM_INCLUDE) \
	-D__BPF_TRACING__ \
	-D__KERNEL__ \
	-DNOCORE \
	-nostdinc \
	-DKBUILD_MODNAME=\"eCapture\" \
	--target=$(BPF_TARGET_TRIPLE) \
	$(TARGET_C_ABI_FLAGS) \
	$(DEBUG_PRINT) \
	-Wall \
	-Wno-unused-variable \
	-Wnounused-but-set-variable \
	-Wno-frame-address \
	-Wno-unused-value \
	-Wno-unknown-warning-option \
	-Wno-pragma-once-outside-header \
	-Wno-pointer-sign \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-deprecated-declarations \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-Wno-unknown-attributes \
	-fno-stack-protector \
	-fno-jump-tables \
	-fno-unwind-tables \
	-fno-asynchronous-unwind-tables

VERSION_FLAG = [CORE]
ENABLECORE = true

ECAPTURE_NAME = $(shell $(CMD_GREP) "Name:" builder/rpmBuild.spec | $(CMD_AWK) '{print $$2}')
RPM_SOURCE0 = $(ECAPTURE_NAME)-$(TAG).tar.gz


#
# output dir
#

OUTPUT_DIR = ./bin

# from CLI args.
RELEASE_NOTES ?= release_notes.txt

# DEB 软件包的名称和版本
PACKAGE_NAME = ecapture
PACKAGE_DESC = eCapture(旁观者): Capture SSL/TLS text content without a CA certificate using eBPF. Supports Linux x86_64/AArch64/LoongArch64 and Android x86_64/AArch64.
PACKAGE_HOMEPAGE = https://ecapture.cc
PACKAGE_MAINTAINER = CFC4N <cfc4n.cs@gmail.com>
PACKAGE_VERSION ?= $(shell $(CMD_ECHO) $(DEB_VERSION) | $(CMD_SED) 's/v//g' )
OUT_DEB_FILE = $(OUTPUT_DIR)/$(PACKAGE_NAME)_$(DEB_VERSION)_linux_$(GOARCH).deb

# 构建目录
BUILD_DIR = build

#
# Create a release snapshot
#

OUT_CHECKSUMS := checksum-$(DEB_VERSION).txt
