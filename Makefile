include variables.mk
include functions.mk

.PHONY: all core nocore env
# include core and non-core ebpf bytecode
all: build
	@echo $(shell date)

# include core ebpf bytecode only
core: build_core
	@echo $(shell date)

# exclude core ebpf
nocore: build_noncore
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
	@echo "HOST_OS                  $(HOST_OS)"
	@echo "UNAME_R                  $(UNAME_R)"
	@echo "CLANG_VERSION            $(CLANG_VERSION)"
	@echo "GO_VERSION               $(GO_VERSION)"
	@echo ---------------------------------------
	@echo "CMD_CLANG                $(CMD_CLANG)"
	@echo "CMD_CC                   $(CMD_CC_PREFIX)$(CMD_CC)"
	@echo "CMD_CXX                  $(CMD_CXX)"
	@echo "CMD_AR                   $(CMD_AR_PREFIX)$(CMD_AR)"
	@echo "CMD_RANLIB               $(CMD_RANLIB)"
	@echo "CMD_READELF              $(CMD_READELF)"
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
	@echo "BPF_TARGET_TRIPLE        $(BPF_TARGET_TRIPLE)"
	@echo "ARCH_BUILD_DIR           $(ARCH_BUILD_DIR)"
	@echo "TARGET_LIBPCAP           $(TARGET_LIBPCAP)"
	@echo "GENERATED_ASSET          $(GENERATED_ASSET)"
	@echo "OUT_BIN                  $(OUT_BIN)"
	@echo "GO_EXTLDFLAGS            $(GO_EXTLDFLAGS)"
	@if [ "$(TARGET_GOARCH)" = loong64 ]; then \
		echo "LOONG64_SYSROOT          $(LOONG64_SYSROOT)"; \
		echo "LOONG64_TARGET_ROOT      $(LOONG64_TARGET_ROOT)"; \
		echo "LOONG64_GCC_RUNTIME_DIR  $(LOONG64_GCC_RUNTIME_DIR)"; \
	fi
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
	@echo "    $$ make core				# build ecapture with CO-RE assets only"
	@echo "    $$ make nocore				# build ecapture with non-CO-RE assets only"
	@echo ""
	@echo "# build rpm"
	@echo "    $$ make rpm VERSION=0.0.0 RELEASE=1		# build ecapture rpm"
	@echo ""
	@echo "# clean"
	@echo "    $$ make clean				# wipe ./bin/ ./bytecode/ ./assets/"
	@echo ""
	@echo "# test"
	@echo "    $$ CROSS_ARCH=arm64 make ...		# cross compile, build eCapture for arm64(aarch64) on amd64(x86_64) host"
	@echo "    $$ CROSS_ARCH=loong64 KERN_HEADERS=/path/to/linux LOONG64_VMLINUX=/path/to/vmlinux make all"
	@echo "    $$ sudo make benchmark-tls			# benchmark OpenSSL overhead and event loss on Linux"
	@echo ""
	@echo "# flags"
	@echo "    $$ ANDROID=1 make ...				# build eCapture for Android"


.PHONY: preflight print-arch-vars prepare
preflight:
	./builder/check-build-environment.sh "$(GOARCH)" "$(TARGET_OS)"

print-arch-vars:
	@printf '%s\n' \
		"GOARCH=$(GOARCH)" \
		"TARGET_ARCH=$(TARGET_ARCH)" \
		"LINUX_ARCH=$(LINUX_ARCH)" \
		"LIBPCAP_ARCH=$(LIBPCAP_ARCH)" \
		"BPF_TARGET_TRIPLE=$(BPF_TARGET_TRIPLE)" \
		"CMD_CLANG=$(CMD_CLANG)" \
		"CMD_CC=$(CMD_CC_PREFIX)$(CMD_CC)" \
		"CMD_CXX=$(CMD_CXX)" \
		"CMD_LLC=$(CMD_LLC)" \
		"CMD_AR=$(CMD_AR_PREFIX)$(CMD_AR)" \
		"CMD_RANLIB=$(CMD_RANLIB)" \
		"CMD_NM=$(CMD_NM)" \
		"CMD_STRIP=$(CMD_STRIP)" \
		"CMD_OBJCOPY=$(CMD_OBJCOPY)" \
		"CMD_OBJDUMP=$(CMD_OBJDUMP)" \
		"CMD_READELF=$(CMD_READELF)" \
		"CMD_LD_LLD=$(CMD_LD_LLD)" \
		"KERNEL_HEADER_GEN=$(KERNEL_HEADER_GEN)" \
		"ARCH_BUILD_DIR=$(ARCH_BUILD_DIR)" \
		"TARGET_LIBPCAP=$(TARGET_LIBPCAP)" \
		"GENERATED_ASSET=$(GENERATED_ASSET)" \
		"OUT_BIN=$(OUT_BIN)" \
		"LIBPCAP_LDFLAGS=$(LIBPCAP_LDFLAGS)" \
		"GO_EXTLDFLAGS=$(GO_EXTLDFLAGS)"

prepare: preflight
	if [ -d "$(LINUX_SOURCE_PATH)" ]; then \
		$(CMD_CD) $(LINUX_SOURCE_PATH) && $(KERNEL_HEADER_GEN) || { echo "Kernel header generation failed"; exit 1; } \
	elif [ -n "$(CROSS_ARCH)" ]; then \
		$(CMD_ECHO) "linux source not found with path: $(LINUX_SOURCE_PATH)"; \
		exit 1; \
    fi

.PHONY: clean assets build ebpf

.PHONY: clean
clean:
	$(CMD_RM) -f bytecode/*.d
	$(CMD_RM) -f bytecode/*.o
	$(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f $(GENERATED_ASSET) $(LEGACY_GENERATED_ASSET)
	$(CMD_RM) -f $(COMPAT_OUT_BIN)
	$(CMD_RM) -f .check*
	$(CMD_RM) -rf $(ARCH_BUILD_DIR)

$(KERN_OBJECTS): $(BYTECODE_DIR)/%_core.o: kern/%.c \
	| .checkver_$(CMD_CLANG) \
	.checkver_$(CMD_GO) \
	preflight \
	autogen
	$(CMD_MKDIR) -p $(BYTECODE_DIR)
	$(CMD_CLANG) -D__TARGET_ARCH_$(LINUX_ARCH) \
		$(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-target bpfel -c $< -o $@ \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP -MF $(@:.o=.d) || exit 1

.PHONY: autogen
autogen: .checkver_$(CMD_BPFTOOL)
	$(AUTOGENCMD)

.PHONY: ebpf
ebpf: autogen $(KERN_OBJECTS)

.PHONY: ebpf_noncore
ebpf_noncore: prepare $(KERN_OBJECTS_NOCORE)

$(KERN_OBJECTS_NOCORE): $(BYTECODE_DIR)/%_noncore.o: kern/%.c \
	| .checkver_$(CMD_CLANG) \
	.checkver_$(CMD_GO) \
	preflight \
	prepare
	set -o pipefail
	$(CMD_MKDIR) -p $(BYTECODE_DIR)
	$(CMD_CLANG) \
			$(EXTRA_CFLAGS_NOCORE) \
			$(BPFHEADER) \
			-I $(KERN_SRC_PATH)/arch/$(LINUX_ARCH)/include \
			-I $(KERN_BUILD_PATH)/arch/$(LINUX_ARCH)/include/generated \
			-I $(KERN_SRC_PATH)/include \
			-I $(KERN_SRC_PATH)/include/linux \
			-I $(KERN_SRC_PATH)/arch/$(LINUX_ARCH)/include/uapi \
			-I $(KERN_BUILD_PATH)/arch/$(LINUX_ARCH)/include/generated/uapi \
			-I $(KERN_SRC_PATH)/include/uapi \
			-I $(KERN_BUILD_PATH)/include/generated/uapi \
			-c $< \
			-o - |$(CMD_LLC) \
			-march=bpf \
			-filetype=obj \
			-o $@ || exit 1

# Generate assets for all eBPF bytecode
.PHONY: assets
assets: .checkver_$(CMD_GO) ebpf ebpf_noncore
	$(CMD_RM) -f assets/ebpf_probe.go assets/ebpf_probe_core.go assets/ebpf_probe_noncore.go $(GENERATED_ASSET) $(LEGACY_GENERATED_ASSET)
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata $(IGNORE_LESS52) -prefix "$(ARCH_BUILD_DIR)/" -pkg assets -o "$(GENERATED_ASSET)" $(wildcard $(BYTECODE_DIR)/*_core.o) $(wildcard $(BYTECODE_DIR)/*_noncore.o)
	sed -i '1s/^\/\/ Code generated/\/\/go:build $(ASSET_BUILD_TAG)\n\n\/\/ Code generated/' $(GENERATED_ASSET)

# Generate assets for core eBPF bytecode only
.PHONY: assets_core
assets_core: \
	.checkver_$(CMD_GO) \
	ebpf
	$(CMD_RM) -f assets/ebpf_probe.go assets/ebpf_probe_core.go assets/ebpf_probe_noncore.go $(GENERATED_ASSET) $(LEGACY_GENERATED_ASSET)
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata $(IGNORE_LESS52) -prefix "$(ARCH_BUILD_DIR)/" -pkg assets -o "$(GENERATED_ASSET)" $(wildcard $(BYTECODE_DIR)/*_core.o)
	sed -i '1s/^\/\/ Code generated/\/\/go:build $(ASSET_BUILD_TAG)\n\n\/\/ Code generated/' $(GENERATED_ASSET)

# Generate assets for non-core eBPF bytecode only
.PHONY: assets_noncore
assets_noncore: \
	.checkver_$(CMD_GO) \
	ebpf_noncore
	$(CMD_RM) -f assets/ebpf_probe.go assets/ebpf_probe_core.go assets/ebpf_probe_noncore.go $(GENERATED_ASSET) $(LEGACY_GENERATED_ASSET)
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata $(IGNORE_LESS52) -prefix "$(ARCH_BUILD_DIR)/" -pkg assets -o "$(GENERATED_ASSET)" $(wildcard $(BYTECODE_DIR)/*_noncore.o)
	sed -i '1s/^\/\/ Code generated/\/\/go:build $(ASSET_BUILD_TAG)\n\n\/\/ Code generated/' $(GENERATED_ASSET)


# Build an architecture-isolated libpcap static library.
$(TARGET_LIBPCAP): | preflight
	test -f ./lib/libpcap/configure || git submodule update --init
	$(CMD_MKDIR) -p $(LIBPCAP_BUILD_DIR)
	cd $(LIBPCAP_BUILD_DIR) && \
		CC="$(CMD_CC_PREFIX)$(CMD_CC)" CXX="$(CMD_CXX)" LD="$(CMD_CC_PREFIX)$(CMD_CC)" \
		AR="$(CMD_AR_PREFIX)$(CMD_AR)" RANLIB="$(CMD_RANLIB)" NM="$(CMD_NM)" STRIP="$(CMD_STRIP)" \
		OBJCOPY="$(CMD_OBJCOPY)" OBJDUMP="$(CMD_OBJDUMP)" READELF="$(CMD_READELF)" \
		CFLAGS="-O2 -g -gdwarf-4 -Wno-unused-result" LDFLAGS="$(LIBPCAP_LDFLAGS)" $(CURDIR)/lib/libpcap/configure --disable-rdma --disable-shared --disable-usb \
			--disable-netmap --disable-bluetooth --disable-dbus --without-libnl \
			--without-dpdk --without-dag --without-septel --without-snf \
			--without-gcc --with-pcap=linux \
			--without-turbocap --host=$(LIBPCAP_ARCH) || { \
				libpcap_configure_status=$$?; \
				$(CMD_CAT) config.log >&2 || true; \
				exit $$libpcap_configure_status; \
			}; \
	$(MAKE) CC="$(CMD_CC_PREFIX)$(CMD_CC)" CXX="$(CMD_CXX)" LD="$(CMD_CC_PREFIX)$(CMD_CC)" \
		AR="$(CMD_AR_PREFIX)$(CMD_AR)" RANLIB="$(CMD_RANLIB)" NM="$(CMD_NM)" STRIP="$(CMD_STRIP)" \
		OBJCOPY="$(CMD_OBJCOPY)" OBJDUMP="$(CMD_OBJDUMP)" READELF="$(CMD_READELF)" || exit 1

# Build binary with both CO-RE and non-CO-RE bytecode
.PHONY: build
build: .checkver_$(CMD_GO) $(TARGET_LIBPCAP) assets
	$(call allow-override,VERSION_FLAG,$(UNAME_R))
	$(call gobuild,$(ANDROID),all)

# Build binary with CO-RE bytecode only
.PHONY: build_core
build_core: \
	.checkver_$(CMD_GO) \
	$(TARGET_LIBPCAP) \
	assets_core
	$(call allow-override,VERSION_FLAG,$(UNAME_R))
	$(call gobuild,$(ANDROID),core)


# Build non-core eBPF bytecode and golang binary
.PHONY: build_noncore
build_noncore: \
	.checkver_$(CMD_GO) \
	$(TARGET_LIBPCAP) \
	assets_noncore
	$(call allow-override,VERSION_FLAG,$(HOST_ARCH))
	$(call gobuild,$(ANDROID),noncore)

# Format the code
.PHONY: format
format:
	@echo "  ->  Formatting code"
	@clang-format -i -style=$(STYLE) kern/*.c
	@clang-format -i -style=$(STYLE) kern/common.h
	@clang-format -i -style=$(STYLE) kern/openssl_untag.h
	@clang-format -i -style=$(STYLE) kern/openssl_masterkey.h
	@clang-format -i -style=$(STYLE) kern/openssl_masterkey_3.0.h
	@clang-format -i -style=$(STYLE) kern/openssl_masterkey_3.2.h
	@clang-format -i -style=$(STYLE) kern/boringssl_masterkey.h
	@clang-format -i -style=$(STYLE) utils/*.c

# run unit tests with race detector
.PHONY: test-race
test-race: \
	.checkver_$(CMD_GO) \
	$(TARGET_LIBPCAP)
	CGO_ENABLED=1 \
	CGO_CFLAGS='-O2 -g -I$(CURDIR)/lib/libpcap/' \
	CGO_LDFLAGS='-O2 -g -L$(CURDIR)/$(LIBPCAP_BUILD_DIR) -lpcap' \
	GOOS=linux GOARCH=$(GOARCH) CC=$(CMD_CC_PREFIX)$(CMD_CC) \
	go test -v -race -tags dynamic,ebpfassets \
		-ldflags "-X github.com/gojue/ecapture/v2/internal/config.ByteCodeFiles=$(BYTECODE_FILES)" \
		./... -coverprofile=coverage.out

# run Bash module e2e test
.PHONY: e2e-bash
e2e-bash:
	bash ./test/e2e/bash_e2e_test.sh

# run Zsh module e2e test
.PHONY: e2e-zsh
e2e-zsh:
	bash ./test/e2e/zsh_e2e_test.sh

# run MySQL module e2e test
.PHONY: e2e-mysql
e2e-mysql:
	bash ./test/e2e/mysql_e2e_test.sh

# run PostgreSQL module e2e test
.PHONY: e2e-postgres
e2e-postgres:
	bash ./test/e2e/postgres_e2e_test.sh

# run TLS module e2e test
.PHONY: e2e-tls
e2e-tls:
	bash ./test/e2e/tls_e2e_test.sh

# run GnuTLS module e2e test
.PHONY: e2e-gnutls
e2e-gnutls:
	bash ./test/e2e/gnutls_e2e_test.sh

# run GoTLS module e2e test
.PHONY: e2e-gotls
e2e-gotls:
	bash ./test/e2e/gotls_e2e_test.sh

# run advanced TLS text mode tests
.PHONY: e2e-tls-text-advanced
e2e-tls-text-advanced:
	E2E_MODULES=tls E2E_MODES=text bash ./test/e2e/run_e2e.sh

# run advanced TLS pcap mode tests
.PHONY: e2e-tls-pcap-advanced
e2e-tls-pcap-advanced:
	E2E_MODULES=tls E2E_MODES=pcapng E2E_STRESS=1 bash ./test/e2e/run_e2e.sh

# run advanced TLS keylog mode tests
.PHONY: e2e-tls-keylog-advanced
e2e-tls-keylog-advanced:
	E2E_MODULES=tls E2E_MODES=keylog bash ./test/e2e/run_e2e.sh

# run advanced GoTLS tests
.PHONY: e2e-gotls-advanced
e2e-gotls-advanced:
	E2E_MODULES=gotls bash ./test/e2e/run_e2e.sh

# run advanced Bash tests
.PHONY: e2e-bash-advanced
e2e-bash-advanced:
	bash ./test/e2e/bash_advanced_test.sh

# run advanced MySQL tests
.PHONY: e2e-mysql-advanced
e2e-mysql-advanced:
	bash ./test/e2e/mysql_advanced_test.sh

# run edge cases and error handling tests
.PHONY: e2e-edge-cases
e2e-edge-cases:
	bash ./test/e2e/edge_cases_test.sh

# run ecaptureQ WebSocket event streaming e2e test
.PHONY: e2e-ecaptureq
e2e-ecaptureq:
	bash ./test/e2e/ecaptureq_e2e_test.sh

# Maintained Linux scope: OpenSSL TLS, GoTLS, and GnuTLS. Every suite covers
# text, keylog, and pcapng modes against a deterministic local TLS endpoint.
.PHONY: e2e-linux
e2e-linux:
	bash ./test/e2e/run_e2e.sh

# run the Linux-only OpenSSL performance/event-loss benchmark
.PHONY: benchmark-tls
benchmark-tls:
	bash ./test/benchmark/tls/run_benchmark.sh

.PHONY: e2e-basic e2e-advanced e2e
e2e-basic: e2e-linux
e2e-advanced:
	E2E_STRESS=1 bash ./test/e2e/run_e2e.sh
e2e: e2e-linux

# Android e2e tests
.PHONY: e2e-android-tls
e2e-android-tls:
	bash ./test/e2e/android/android_tls_e2e_test.sh

.PHONY: e2e-android-all
e2e-android-all: e2e-android-tls
	@echo "All Android e2e tests completed"

.PHONY: build-android-tests
build-android-tests:
	bash ./test/e2e/android/build_android_tests.sh

.PHONY: setup-android-env
setup-android-env:
	bash ./test/e2e/android/setup_android_env.sh
