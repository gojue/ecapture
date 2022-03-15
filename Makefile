TARGETS := kern/ssldump

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=_kern.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}

LLC ?= llc
CLANG ?= clang
EXTRA_CFLAGS ?= -O2 -mcpu=v1 -nostdinc -Wno-pointer-sign

BPFHEADER = -I./kern \
		-I/usr/include \
		-I/home/cfc4n/download/linux-5.11.0/include \
		-I/home/cfc4n/download/linux-5.11.0/tools/lib

all: $(KERN_OBJECTS) assets build
	@echo $(shell date)

.PHONY: clean assets

clean:
	rm -f user/bytecode/*.d
	rm -f user/bytecode/*.o
	rm -f assets/ebpf_probe.go
	rm -f bin/ssldump

$(KERN_OBJECTS): %.o: %.c
	$(CLANG) $(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-target bpfel -c $< -o $(subst kern/,user/bytecode/,$@) \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP

assets:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/bytecode/*.o)

build:
	CGO_ENABLED=0 go build -o bin/ssldump .