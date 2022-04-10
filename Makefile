.PHONY: all | env
all: ebpf assets build
	@echo $(shell date)

# centos 8.2  4.18.0-305.3.1.el8.x86_64
# centos 8.2     gcc Version 8.4.1 20200928 (Red Hat 8.4.1-1) (GCC)
# clang 12.0.1-4.module_el8.5.0+1025+93159d6c

.ONESHELL:
SHELL = /bin/sh

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
MAKE = make

CMD_LLC ?= llc
CMD_TR ?= tr
CMD_CUT ?= cut
CMD_AWK ?= awk
CMD_SED ?= sed
CMD_GIT ?= git
CMD_CLANG ?= clang
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

.check_%:
#
	@command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi


EXTRA_CFLAGS ?= -O2 -mcpu=v1 \
	-DDEBUG_PRINT	\
	-nostdinc \
	-Wno-pointer-sign

BPFHEADER = -I./kern \

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

#TODO  系统内核版本检测  5.8 以上

#  clang 编译器版本检测，llvm检测，
.checkver_$(CMD_CLANG): \
	| .check_$(CMD_CLANG)
#
	@echo $(shell date)
	@if [ ${CLANG_VERSION} -lt 12 ]; then
		echo -n "you MUST use clang 12 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	$(CMD_TOUCH) $@ # avoid target rebuilds over and over due to inexistent file

GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)


# golang 版本检测  1.16 以上
.checkver_$(CMD_GO): \
	| .check_$(CMD_GO)
#
	@if [ ${GO_VERSION_MAJ} -eq 1 ]; then
		if [ ${GO_VERSION_MIN} -lt 16 ]; then
			echo -n "you MUST use golang 1.16 or newer, "
			echo "your current golang version is ${GO_VERSION}"
			exit 1
		fi
	fi
	touch $@

#
# version
#
# tags date info
TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")
LAST_GIT_TAG := $(TAG:v%=%)-$(DATE)-$(COMMIT)
ifneq ($(COMMIT), $(TAG_COMMIT))
	LAST_GIT_TAG := $(LAST_GIT_TAG)-prev-$(TAG_COMMIT)
endif

ifneq ($(shell git status --porcelain),)
	LAST_GIT_TAG := $(LAST_GIT_TAG)-dirty
endif

#LAST_GIT_TAG ?= $(shell $(CMD_GIT) describe --tags --match 'v*' 2>/dev/null)
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(LAST_GIT_TAG))

#
# environment
#

UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

#
# Target Arch
#

ifeq ($(UNAME_M),x86_64)
   ARCH = x86_64
   LINUX_ARCH = x86
   GO_ARCH = amd64
endif

ifeq ($(UNAME_M),aarch64)
   ARCH = arm64
   LINUX_ARCH = arm64
   GO_ARCH = arm64
endif

KERN_RELEASE ?= $(UNAME_R)
KERN_BUILD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BUILD_PATH)))

BPF_NOCORE_TAG = $(subst .,_,$(KERN_RELEASE)).$(subst .,_,$(VERSION))


#
# BPF Source file
#

TARGETS := kern/openssl
TARGETS += kern/bash
TARGETS += kern/gnutls
TARGETS += kern/nspr
TARGETS += kern/mysqld

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=_kern.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}


.PHONY: env
env:
	@echo ---------------------------------------
	@echo "Makefile Environment:"
	@echo ---------------------------------------
	@echo "PARALLEL                 $(PARALLEL)"
	@echo ---------------------------------------
	@echo "CLANG_VERSION            $(CLANG_VERSION)"
	@echo "GO_VERSION               $(GO_VERSION)"
	@echo ---------------------------------------
	@echo "CMD_CLANG                $(CMD_CLANG)"
	@echo "CMD_GIT                  $(CMD_GIT)"
	@echo "CMD_GO                   $(CMD_GO)"
	@echo "CMD_INSTALL              $(CMD_INSTALL)"
	@echo "CMD_LLC                  $(CMD_LLC)"
	@echo "CMD_MD5                  $(CMD_MD5)"
	@echo "CMD_PKGCONFIG            $(CMD_PKGCONFIG)"
	@echo "CMD_STRIP                $(CMD_STRIP)"
	@echo "VERSION                  $(VERSION)"
	@echo "LAST_GIT_TAG             $(LAST_GIT_TAG)"
	@echo "BPF_NOCORE_TAG           $(BPF_NOCORE_TAG)"
	@echo ---------------------------------------
	@echo "UNAME_M                  $(UNAME_M)"
	@echo "UNAME_R                  $(UNAME_R)"
	@echo "ARCH                     $(ARCH)"
	@echo "LINUX_ARCH               $(LINUX_ARCH)"
	@echo ---------------------------------------
	@echo "KERN_RELEASE             $(KERN_RELEASE)"
	@echo "KERN_BUILD_PATH          $(KERN_BUILD_PATH)"
	@echo "KERN_SRC_PATH            $(KERN_SRC_PATH)"
	@echo ---------------------------------------
	@echo "GO_ARCH                  $(GO_ARCH)"
	@echo ---------------------------------------

#
# usage
#

.PHONY: help
help:
	@echo "# environment"
	@echo "    $$ make env		# show makefile environment/variables"
	@echo ""
	@echo "# build"
	@echo "    $$ make all		# build ecapture"
	@echo ""
	@echo "# clean"
	@echo "    $$ make clean		# wipe ./bin/ ./user/bytecode/ ./assets/"
	@echo ""
	@echo "# test"
	@echo "    $$ make test		# run all go"
	@echo ""
	@echo "# flags"
	@echo "    $$ CORE=0 make ...		# build NOCORE ebpf"

.PHONY: clean assets build ebpf

.PHONY: clean
clean:
	$(CMD_RM) -f user/bytecode/*.d
	$(CMD_RM) -f user/bytecode/*.o
	$(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f bin/ecapture
	$(CMD_RM) -f .check*

.PHONY: $(KERN_OBJECTS)
$(KERN_OBJECTS): %.o: %.c \
	| .checkver_$(CMD_CLANG) \
	.checkver_$(CMD_GO)
	$(CMD_CLANG) -D__TARGET_ARCH_$(LINUX_ARCH) \
		$(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-target bpfel -c $< -o $(subst kern/,user/bytecode/,$@) \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP

.PHONY: ebpf
ebpf: $(KERN_OBJECTS)

.PHONY: assets
assets: \
	.checkver_$(CMD_GO)
#
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/bytecode/*.o)


.PHONY: build
build: \
	.checkver_$(CMD_GO)
#
	CGO_ENABLED=0 $(CMD_GO) build -ldflags "-w -s -X 'ecapture/cli/cmd.GitVersion=$(VERSION)'" -o bin/ecapture .
