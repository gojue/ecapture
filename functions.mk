
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


# golang 版本检测  1.21 以上
.checkver_$(CMD_GO): \
	| .check_$(CMD_GO)
	@if [ ${GO_VERSION_MAJ} -eq 1 ]; then
		if [ ${GO_VERSION_MIN} -lt 21 ]; then
			echo -n "you MUST use golang 1.21 or newer, "
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
	CGO_CFLAGS='-O2 -g -gdwarf-4 -I$(CURDIR)/lib/libpcap/' \
	CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/libpcap -lpcap -static' \
	GOOS=linux GOARCH=$(GOARCH) CC=$(CMD_CLANG) \
	$(CMD_GO) build -tags $(TARGET_TAG) -ldflags "-w -s -X 'ecapture/cli/cmd.GitVersion=$(TARGET_TAG)_$(UNAME_M):$(VERSION):$(VERSION_FLAG)' -X 'main.enableCORE=$(ENABLECORE)'" -o $(OUT_BIN)
    @if [$(1) -eq 0 ]; then
		$(OUT_BIN) -v
    fi
endef
