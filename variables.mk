MAKE = make
CMD_LLC ?= llc
CMD_TR ?= tr
CMD_CUT ?= cut
CMD_AWK ?= awk
CMD_SED ?= sed
CMD_GIT ?= git
CMD_CLANG ?= clang
CMD_GCC ?= gcc
CMD_AR ?= ar
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
KERNEL_LESS_5_2_PREFIX ?= _less52.o
STYLE    ?= "{BasedOnStyle: Google, IndentWidth: 4}"
IGNORE_LESS52 ?=
AUTOGENCMD ?=
BPFHEADER := -I ./kern
SUDO ?=
LIBPCAP_ARCH ?=
GOARCH ?=
DEBUG_PRINT ?=
CROSS_COMPILE ?=
TARGET_ARCH = x86_64
# Use clang as default compiler for both libpcap and cgo.
CGO_ENABLED = 1
TARGET_LIBPCAP = ./lib/libpcap.a
TARGET_TAG ?= linux


ifndef DEBUG
	DEBUG = 0
endif

ifeq ($(DEBUG),1)
	DEBUG_PRINT := -DDEBUG_PRINT
endif

ifndef ANDROID
	ANDROID = 0
endif

ifeq ($(ANDROID),1)
	TARGET_TAG := androidgki
	IGNORE_LESS52 = -ignore '.*_less52\.o'
endif

EXTRA_CFLAGS ?= -O2 -mcpu=v1 \
	$(DEBUG_PRINT)	\
	-nostdinc \
	-Wno-pointer-sign

EXTRA_CFLAGS_NOCORE ?= -emit-llvm -O2 -S\
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	-xc -g \
	-D__BPF_TRACING__ \
	-D__KERNEL__ \
	-DNOCORE \
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

#
# tools version
#
CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)

# tags date info
TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")
LAST_GIT_TAG := $(TAG:v%=%)-$(DATE)-$(COMMIT)
RPM_RELEASE := $(DATE).$(COMMIT)

VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(LAST_GIT_TAG))

#
# environment
#
UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

ifdef CROSS_ARCH
	ifeq ($(UNAME_M),aarch64)
		ifeq ($(CROSS_ARCH),amd64)
		# cross compile
			CROSS_COMPILE = x86_64-linux-gnu-
		else
		# not cross compile
			TARGET_ARCH = $(UNAME_M)
		endif
	else ifeq ($(UNAME_M),x86_64)
		ifeq ($(CROSS_ARCH),arm64)
		# cross compile
			CROSS_COMPILE = aarch64-linux-gnu-
		else
		# not cross compile
			TARGET_ARCH = $(UNAME_M)
		endif
	else
		# not support
	endif
else
	TARGET_ARCH = $(UNAME_M)
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
	 AUTOGENCMD = ls -al kern/bpf/arm64/vmlinux.h
	 BPFHEADER += -I ./kern/bpf/arm64
	 LIBPCAP_ARCH = aarch64-unknown-linux-gnu
else
	# x86_64 default
	LINUX_ARCH = x86
	GOARCH = amd64
	BPFHEADER += -I ./kern/bpf/x86
	AUTOGENCMD = test -f kern/bpf/x86/vmlinux.h || $(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/bpf/x86/vmlinux.h
	LIBPCAP_ARCH = x86_64-unknown-linux-gnu
endif

#
# include vpath
#

KERN_RELEASE ?= $(UNAME_R)
KERN_BUILD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BUILD_PATH)))

BPF_NOCORE_TAG = $(subst .,_,$(KERN_RELEASE)).$(subst .,_,$(VERSION))

#
# BPF Source file
#
TARGETS := kern/boringssl_a_13
TARGETS += kern/boringssl_a_14
TARGETS += kern/openssl_1_1_1a
TARGETS += kern/openssl_1_1_1b
TARGETS += kern/openssl_1_1_1d
TARGETS += kern/openssl_1_1_1j
TARGETS += kern/openssl_1_1_0a
TARGETS += kern/openssl_1_0_2a
TARGETS += kern/openssl_3_0_0
TARGETS += kern/openssl_3_2_0
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

VERSION_FLAG = [CORE]
ENABLECORE = true
OUT_BIN = bin/ecapture

ECAPTURE_NAME = $(shell $(CMD_GREP) "Name:" builder/rpmBuild.spec | $(CMD_AWK) '{print $$2}')
RPM_SOURCE0 = $(ECAPTURE_NAME)-$(TAG).tar.gz
