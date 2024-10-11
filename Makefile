include variables.mk
include functions.mk

.PHONY: all | env nocore
# include core and non-core ebpf bytecode
all: ebpf ebpf_noncore assets build
	@echo $(shell date)

# exclude core ebpf
nocore: ebpf_noncore assets_noncore build_noncore
	@echo $(shell date)

noncore: nocore
ebpf_nocore: ebpf_noncore

.ONESHELL:
SHELL = /bin/bash

.PHONY: env
env:
	@echo ---------------------------------------
	@echo "eCapture Makefile Environment:"
	@echo ---------------------------------------
	@echo "PARALLEL                 $(PARALLEL)"
	@echo ----------------[ from args ]---------------
	@echo "CROSS_ARCH               $(CROSS_ARCH)"
	@echo "ANDROID                  $(ANDROID)"
	@echo "DEBUG                    $(DEBUG)"
	@echo "SNAPSHOT_VERSION         $(SNAPSHOT_VERSION)"
	@echo ---------------------------------------
	@echo "HOST_ARCH                $(HOST_ARCH)"
	@echo "UNAME_R                  $(UNAME_R)"
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
	@echo "CMD_CC_PREFIX            $(CMD_CC_PREFIX)"
	@echo "CMD_TAR                  $(CMD_TAR)"
	@echo "CMD_RPMBUILD             $(CMD_RPMBUILD)"
	@echo "CMD_RPM_SETUP_TREE       $(CMD_RPM_SETUP_TREE)"
	@echo ---------------------------------------
	@echo "VERSION_NUM              $(VERSION_NUM)"
	@echo "LAST_GIT_TAG             $(LAST_GIT_TAG)"
	@echo "BPF_NOCORE_TAG           $(BPF_NOCORE_TAG)"
	@echo "KERN_RELEASE             $(KERN_RELEASE)"
	@echo "LINUX_SOURCE_PATH        $(LINUX_SOURCE_PATH)"
	@echo "KERN_BUILD_PATH          $(KERN_BUILD_PATH)"
	@echo "KERN_SRC_PATH            $(KERN_SRC_PATH)"
	@echo "TARGET_ARCH              $(TARGET_ARCH)"
	@echo "GOARCH                   $(GOARCH)"
	@echo "LINUX_ARCH               $(LINUX_ARCH)"
	@echo "LIBPCAP_ARCH             $(LIBPCAP_ARCH)"
	@echo "AUTOGENCMD               $(AUTOGENCMD)"
	@echo "PACKAGE_VERSION          $(PACKAGE_VERSION)"
	@echo "OUT_DEB_FILE             $(OUT_DEB_FILE)"
	@echo ---------------------------------------

.PHONY:rpm
rpm:
	@$(CMD_RPM_SETUP_TREE) || exit 1
	$(CMD_SED) -i '0,/^Version:.*$$/s//Version:    $(TAG)/' builder/rpmBuild.spec
	$(CMD_SED) -i '0,/^Release:.*$$/s//Release:    $(RPM_RELEASE)/' builder/rpmBuild.spec
	$(CMD_TAR) zcvf ~/rpmbuild/SOURCES/$(RPM_SOURCE0) ./
	$(CMD_RPMBUILD) -ba builder/rpmBuild.spec

#
# usage
#

.PHONY: help
help:
	@echo "# environment"
	@echo "    $$ make env					# show makefile environment/variables"
	@echo ""
	@echo "# build"
	@echo "    $$ make all					# build ecapture"
	@echo ""
	@echo "# build rpm"
	@echo "    $$ make rpm VERSION=0.0.0 RELEASE=1		# build ecapture rpm"
	@echo ""
	@echo "# clean"
	@echo "    $$ make clean				# wipe ./bin/ ./user/bytecode/ ./assets/"
	@echo ""
	@echo "# test"
	@echo "    $$ CROSS_ARCH=arm64 make ...		# cross compile, build eCapture for arm64(aarch64) on amd64(x86_64) host"
	@echo ""
	@echo "# flags"
	@echo "    $$ ANDROID=1 make ...				# build eCapture for Android"


.PHONY: prepare
prepare:
	if [ -d "$(LINUX_SOURCE_PATH)" ]; then \
		$(CMD_CD) $(LINUX_SOURCE_PATH) && $(KERNEL_HEADER_GEN) || { echo "Kernel header generation failed"; exit 1; } \
	elif [ -n "$(CROSS_ARCH)" ]; then \
		$(CMD_ECHO) "linux source not found with path: $(LINUX_SOURCE_PATH)" || exit 1; \
    fi

.PHONY: clean assets build ebpf

.PHONY: clean
clean:
	$(CMD_RM) -f user/bytecode/*.d
	$(CMD_RM) -f user/bytecode/*.o
	$(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f bin/ecapture
	$(CMD_RM) -f .check*
	@if [ -e ./lib/libpcap/Makefile ] ; then \
		cd ./lib/libpcap && make clean
	fi

.PHONY: $(KERN_OBJECTS)
$(KERN_OBJECTS): %.o: %.c \
	| .checkver_$(CMD_CLANG) \
	.checkver_$(CMD_GO) \
	autogen
	$(CMD_CLANG) -D__TARGET_ARCH_$(LINUX_ARCH) \
		$(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-target bpfel -c $< -o $(subst kern/,user/bytecode/,$(subst .o,_core.o,$@)) \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP
	$(CMD_CLANG) -D__TARGET_ARCH_$(LINUX_ARCH) \
		$(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-DKERNEL_LESS_5_2 \
		-target bpfel -c $< -o $(subst kern/,user/bytecode/,$(subst .c,_core$(KERNEL_LESS_5_2_PREFIX),$<)) \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP

.PHONY: autogen
autogen: .checkver_$(CMD_BPFTOOL)
	$(AUTOGENCMD)

.PHONY: ebpf
ebpf: autogen $(KERN_OBJECTS)

.PHONY: ebpf_noncore
ebpf_noncore: prepare $(KERN_OBJECTS_NOCORE)

.PHONY: $(KERN_OBJECTS_NOCORE)
$(KERN_OBJECTS_NOCORE): %.nocore: %.c \
	| .checkver_$(CMD_CLANG) \
	.checkver_$(CMD_GO) \
	prepare
	$(CMD_CLANG) \
			$(EXTRA_CFLAGS_NOCORE) \
			$(BPFHEADER) \
			-I $(KERN_SRC_PATH)/arch/$(LINUX_ARCH)/include \
			-I $(KERN_BUILD_PATH)/arch/$(LINUX_ARCH)/include/generated \
			-I $(KERN_SRC_PATH)/include \
			-I $(KERN_SRC_PATH)/arch/$(LINUX_ARCH)/include/uapi \
			-I $(KERN_BUILD_PATH)/arch/$(LINUX_ARCH)/include/generated/uapi \
			-I $(KERN_SRC_PATH)/include/uapi \
			-I $(KERN_BUILD_PATH)/include/generated/uapi \
			-c $< \
			-o - |$(CMD_LLC) \
			-march=bpf \
			-filetype=obj \
			-o $(subst kern/,user/bytecode/,$(subst .c,_noncore.o,$<))
	$(CMD_CLANG) \
			$(EXTRA_CFLAGS_NOCORE) \
			$(BPFHEADER) \
			-I $(KERN_SRC_PATH)/arch/$(LINUX_ARCH)/include \
			-I $(KERN_BUILD_PATH)/arch/$(LINUX_ARCH)/include/generated \
			-I $(KERN_SRC_PATH)/include \
			-I $(KERN_SRC_PATH)/arch/$(LINUX_ARCH)/include/uapi \
			-I $(KERN_BUILD_PATH)/arch/$(LINUX_ARCH)/include/generated/uapi \
			-I $(KERN_SRC_PATH)/include/uapi \
			-I $(KERN_BUILD_PATH)/include/generated/uapi \
			-DKERNEL_LESS_5_2 \
			-c $< \
			-o - |$(CMD_LLC) \
			-march=bpf \
			-filetype=obj \
			-o $(subst kern/,user/bytecode/,$(subst .c,_noncore$(KERNEL_LESS_5_2_PREFIX),$<))

.PHONY: assets
assets: \
	.checkver_$(CMD_GO) \
	ebpf \
	ebpf_noncore
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata $(IGNORE_LESS52) -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/bytecode/*.o)

.PHONY: assets_noncore
assets_noncore: \
	.checkver_$(CMD_GO) \
	ebpf_noncore
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata $(IGNORE_LESS52) -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/bytecode/*.o)


.PHONY: $(TARGET_LIBPCAP)
$(TARGET_LIBPCAP):
	test -f ./lib/libpcap/configure || git submodule update --init
	cd lib/libpcap && \
		CC=$(CMD_CC_PREFIX)$(CMD_CC) AR=$(CMD_AR_PREFIX)$(CMD_AR) CFLAGS="-O2 -g -gdwarf-4 -static -Wno-unused-result" ./configure --disable-rdma --disable-shared --disable-usb \
			--disable-netmap --disable-bluetooth --disable-dbus --without-libnl \
			--without-dpdk --without-dag --without-septel --without-snf \
			--without-gcc --with-pcap=linux \
			--without-turbocap --host=$(LIBPCAP_ARCH) && \
	CC=$(CMD_CC_PREFIX)$(CMD_CC) AR=$(CMD_AR_PREFIX)$(CMD_AR) make

.PHONY: build
build: \
	.checkver_$(CMD_GO) \
	$(TARGET_LIBPCAP) \
	assets \
	assets_noncore
	$(call allow-override,VERSION_FLAG,$(UNAME_R))
	$(call gobuild, $(ANDROID))


.PHONY: build_noncore
build_noncore: \
	.checkver_$(CMD_GO) \
	$(TARGET_LIBPCAP) \
	assets_noncore
	$(call allow-override,VERSION_FLAG,$(HOST_ARCH))
	$(call gobuild, $(ANDROID))

# Format the code
.PHONY: format
format:
	@echo "  ->  Formatting code"
	@clang-format -i -style=$(STYLE) kern/*.c
	@clang-format -i -style=$(STYLE) kern/common.h
	@clang-format -i -style=$(STYLE) kern/openssl_masterkey.h
	@clang-format -i -style=$(STYLE) kern/openssl_masterkey_3.0.h
	@clang-format -i -style=$(STYLE) kern/openssl_masterkey_3.2.h
	@clang-format -i -style=$(STYLE) kern/boringssl_masterkey.h
	@clang-format -i -style=$(STYLE) utils/*.c
