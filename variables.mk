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
CMD_CC_PREFIX ?=
CMD_AR ?= ar
CMD_AR_PREFIX ?=
CMD_STRIP ?= llvm-strip
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

KERNEL_LESS_5_2_PREFIX ?= _less52.o
STYLE    ?= "{BasedOnStyle: Google, IndentWidth: 4, TabWidth: 4, UseTab: Never, ColumnLimit: 120}"
IGNORE_LESS52 ?=
AUTOGENCMD ?=
BPFHEADER := -I ./kern
SUDO ?=
LIBPCAP_ARCH ?=
GOARCH ?=
DEBUG_PRINT ?=
TARGET_ARCH = x86_64
# Use clang as default compiler for both libpcap and cgo.
CGO_ENABLED = 1
TARGET_LIBPCAP = ./lib/libpcap.a
TARGET_TAG ?= linux
KERNEL_HEADER_GEN ?= whoami

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
	TARGET_TAG := androidgki
	TARGET_OS = android
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
LAST_GIT_TAG := $(TAG:v%=%)-$(DATE)-$(COMMIT)
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

HOST_ARCH := $(shell uname -m)
UNAME_R := $(shell uname -r)
HOST_VERSION_SHORT := $(shell uname -r | cut -d'-' -f 1)
LINUX_SOURCE_FILE := $(shell find /usr/src -maxdepth 1 -name "*linux-source*.tar.bz2")
LINUX_SOURCE_PATH := $(shell echo $(LINUX_SOURCE_FILE) | $(CMD_SED) 's/\.tar\.bz2//g')

ifdef CROSS_ARCH
	ifeq ($(HOST_ARCH),aarch64)
		ifeq ($(CROSS_ARCH),amd64)
		# cross compile
			CMD_CC_PREFIX = x86_64-linux-gnu-
			CMD_AR_PREFIX = x86_64-linux-gnu-
			TARGET_ARCH = x86_64
		else
		# not cross compile
			TARGET_ARCH = $(HOST_ARCH)
		endif
	else ifeq ($(HOST_ARCH),x86_64)
		ifeq ($(CROSS_ARCH),arm64)
		# cross compile
			CMD_CC_PREFIX = aarch64-linux-gnu-
			CMD_AR_PREFIX = aarch64-linux-gnu-
			TARGET_ARCH = aarch64
		else
		# not cross compile
			TARGET_ARCH = $(HOST_ARCH)
		endif
	else
		# not support
	endif
else
	TARGET_ARCH = $(HOST_ARCH)
endif

# Determine whether the command sudo exists
# on docerk or the arm64 docker simulated by qemu, the sudo command does not exist
ifeq ($(shell command -v sudo 2> /dev/null),)
	SUDO =
else
	SUDO = sudo
endif

ifeq ($(TARGET_ARCH),aarch64)
	 LINUX_ARCH = arm64
	 GOARCH = arm64
	 BPFHEADER += -I ./kern/bpf/$(LINUX_ARCH)
	 AUTOGENCMD = ls -al kern/bpf/$(LINUX_ARCH)/vmlinux.h
	 # sh lib/libpcap/config.sub arm64-linux for ARCH value
	 LIBPCAP_ARCH = aarch64-unknown-linux-gnu
	 # Constant replacement is not supported in the current version because the bpf_probe_read_user function
	 # which supports eBPF on the aarch architecture of the Linux Kernel, has been supported since version 5.5,
	 # which is higher than the constant replacement feature of cilium/ebpf
	 IGNORE_LESS52 = -ignore '.*_less52\.o'
else
	# x86_64 default
	LINUX_ARCH = x86
	GOARCH = amd64
	BPFHEADER += -I ./kern/bpf/$(LINUX_ARCH)
	AUTOGENCMD = test -f kern/bpf/$(LINUX_ARCH)/vmlinux.h || $(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/bpf/$(LINUX_ARCH)/vmlinux.h
	 # sh lib/libpcap/config.sub amd64-linux or x86_64-linux for ARCH value
	LIBPCAP_ARCH = x86_64-pc-linux-gnu
endif

#
# include vpath
#
ifdef CROSS_ARCH
	KERNEL_HEADER_GEN = yes "" | $(SUDO) make ARCH=$(LINUX_ARCH) CROSS_COMPILE=$(CMD_CC_PREFIX) prepare V=0
	ifdef KERN_HEADERS
		LINUX_SOURCE_PATH = $(KERN_HEADERS)
	else
		KERN_HEADERS = $(LINUX_SOURCE_PATH)
    endif
endif

KERN_RELEASE ?= $(UNAME_R)
KERN_BUILD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BUILD_PATH)))

BPF_NOCORE_TAG = $(subst .,_,$(KERN_RELEASE)).$(subst .,_,$(VERSION_NUM))

#
# BPF Source file
#
TARGETS := kern/boringssl_na
TARGETS += kern/boringssl_a_13
TARGETS += kern/boringssl_a_14
TARGETS += kern/openssl_1_1_1a
TARGETS += kern/openssl_1_1_1b
TARGETS += kern/openssl_1_1_1d
TARGETS += kern/openssl_1_1_1j
TARGETS += kern/openssl_1_1_0a
TARGETS += kern/openssl_1_0_2a
TARGETS += kern/openssl_3_0_0
TARGETS += kern/openssl_3_2_0
TARGETS += kern/openssl_3_2_3
TARGETS += kern/openssl_3_3_0
TARGETS += kern/openssl_3_3_2
TARGETS += kern/gotls

ifeq ($(ANDROID),0)
	TARGETS += kern/bash
	TARGETS += kern/gnutls
	TARGETS += kern/nspr
	TARGETS += kern/mysqld
	TARGETS += kern/postgres
endif


# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=_kern.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
KERN_OBJECTS_NOCORE = ${KERN_SOURCES:.c=.nocore}


EXTRA_CFLAGS ?= -O2 -mcpu=v1 \
	$(DEBUG_PRINT)	\
	-nostdinc \
	-Wno-pointer-sign

EXTRA_CFLAGS_NOCORE ?= -emit-llvm -O2 -S\
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	-xc -g -isystem \
	-D__BPF_TRACING__ \
	-D__KERNEL__ \
	-DNOCORE \
	-nostdinc \
	-DKBUILD_MODNAME=\"eCapture\" \
	-target $(TARGET_ARCH) \
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
	-fno-stack-protector \
	-fno-jump-tables \
	-fno-unwind-tables \
	-fno-asynchronous-unwind-tables

VERSION_FLAG = [CORE]
ENABLECORE = true
OUT_BIN = bin/ecapture

ECAPTURE_NAME = $(shell $(CMD_GREP) "Name:" builder/rpmBuild.spec | $(CMD_AWK) '{print $$2}')
RPM_SOURCE0 = $(ECAPTURE_NAME)-$(TAG).tar.gz


#
# output dir
#

OUTPUT_DIR = ./bin
#TAR_DIR = ecapture-$(DEB_VERSION)-linux-$(GOARCH)
#TAR_DIR_NOCORE = ecapture-$(DEB_VERSION)-linux-$(GOARCH)-nocore
#TAR_DIR_ANDROID = ecapture-$(DEB_VERSION)-android-$(GOARCH)
#TAR_DIR_ANDROID_NOCORE = ecapture-$(DEB_VERSION)-android-$(GOARCH)-nocore

# from CLI args.
RELEASE_NOTES ?= release_notes.txt

# DEB 软件包的名称和版本
PACKAGE_NAME = ecapture
PACKAGE_DESC = eCapture(旁观者): Capture SSL/TLS text content without a CA certificate using eBPF. This tool is compatible with Linux/Android x86_64/Aarch64.
PACKAGE_HOMEPAGE = https://ecapture.cc
PACKAGE_MAINTAINER = CFC4N <cfc4n.cs@gmail.com>
PACKAGE_VERSION ?= $(shell $(CMD_ECHO) $(DEB_VERSION) | $(CMD_SED) 's/v//g' )
OUT_DEB_FILE = $(OUTPUT_DIR)/$(PACKAGE_NAME)_$(DEB_VERSION)_linux_$(GOARCH).deb

# 构建目录
BUILD_DIR = build

#
# Create a release snapshot
#

#OUT_ARCHIVE := $(OUTPUT_DIR)/$(TAR_DIR).tar.gz
#OUT_ARCHIVE_NOCORE := $(OUTPUT_DIR)/$(TAR_DIR_NOCORE).tar.gz
#OUT_ARCHIVE_ANDROID := $(OUTPUT_DIR)/$(TAR_DIR_ANDROID).tar.gz
#OUT_ARCHIVE_ANDROID_NOCORE := $(OUTPUT_DIR)/$(TAR_DIR_ANDROID_NOCORE).tar.gz
OUT_CHECKSUMS := checksum-$(DEB_VERSION).txt
