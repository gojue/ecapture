
.check_%:
	@command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "eCapture Makefile: missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi


#  clang 编译器版本检测，llvm检测，
.checkver_$(CMD_CLANG): \
	| .check_$(CMD_CLANG)
#
	@echo $(shell date)
	@if [ ${CLANG_VERSION} -lt 9 ]; then
		echo -n "you MUST use clang 9 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	$(CMD_TOUCH) $@ # avoid target rebuilds over and over due to inexistent file


# golang 版本检测  1.26 以上
.checkver_$(CMD_GO): \
	| .check_$(CMD_GO)
	@if [ ${GO_VERSION_MAJ} -eq 1 ]; then
		if [ ${GO_VERSION_MIN} -lt 26 ]; then
			echo -n "you MUST use golang 1.26 or newer, "
			echo "your current golang version is ${GO_VERSION}"
			exit 1
		fi
	fi
	touch $@

# bpftool version
.checkver_$(CMD_BPFTOOL): \
	| .check_$(CMD_BPFTOOL)

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

define gobuild
	$(CMD_MKDIR) -p $(dir $(OUT_BIN)) $(dir $(COMPAT_OUT_BIN))
	CGO_ENABLED=1 \
	CGO_CFLAGS='-O2 -g -gdwarf-4 -I$(CURDIR)/lib/libpcap/' \
	CGO_LDFLAGS='-O2 -g -L$(CURDIR)/$(LIBPCAP_BUILD_DIR) -lpcap $(CGO_LINK_FLAGS)' \
	GOOS=linux GOARCH=$(GOARCH) CC=$(CMD_CC_PREFIX)$(CMD_CC) CXX=$(CMD_CXX) \
	AR=$(CMD_AR_PREFIX)$(CMD_AR) RANLIB=$(CMD_RANLIB) NM=$(CMD_NM) \
	$(CMD_GO) build -trimpath -buildmode=pie -mod=readonly -tags '$(TARGET_TAG),netgo,ebpfassets,dynamic' -ldflags "-w -s -X 'github.com/gojue/ecapture/v2/cli/cmd.GitVersion=$(TARGET_TAG)_$(GOARCH):$(VERSION_NUM):$(VERSION_FLAG)' -X 'github.com/gojue/ecapture/v2/internal/config.ByteCodeFiles=$(2)' -linkmode=external -extld=$(CMD_CC_PREFIX)$(CMD_CC) -extldflags '$(GO_EXTLDFLAGS)'" -o $(OUT_BIN) || exit 1
	$(CMD_CP) $(OUT_BIN) $(COMPAT_OUT_BIN) || exit 1
	$(CMD_FILE) $(OUT_BIN) || exit 1
endef


define CHECK_IS_NON_CORE
$(if $(filter $(1),$(2)),-nocore,)
endef

# build and tar
define release_tar
	$(call allow-override,CORE_PREFIX,$(call CHECK_IS_NON_CORE,$(2),nocore))
	$(call allow-override,TAR_DIR,ecapture-$(DEB_VERSION)-$(1)-$(GOARCH)$(CORE_PREFIX))
	$(call allow-override,OUT_ARCHIVE,$(OUTPUT_DIR)/$(TAR_DIR).tar.gz)
	$(CMD_MAKE) clean
	ANDROID=$(ANDROID) $(CMD_MAKE) $(2)
	# create the tar ball and checksum files
	$(CMD_MKDIR) -p $(TAR_DIR)
	$(CMD_CP) LICENSE $(TAR_DIR)/LICENSE
	$(CMD_CP) CHANGELOG.md $(TAR_DIR)/CHANGELOG.md
	$(CMD_CP) README.md $(TAR_DIR)/README.md
	$(CMD_CP) README-zh_Hans.md $(TAR_DIR)/README-zh_Hans.md
	$(CMD_CP) $(OUT_BIN) $(TAR_DIR)/ecapture
	$(CMD_TAR) -czf $(OUT_ARCHIVE) $(TAR_DIR)
endef
