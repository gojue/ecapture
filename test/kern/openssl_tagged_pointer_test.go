// Package kern guards source-level invariants in the eBPF probes that are not
// practical to exercise from a Go unit test.
package kern

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	pointerMaskRE = regexp.MustCompile(`(?m)^#define\s+OPENSSL_USER_POINTER_MASK\s+(0x[0-9a-fA-F]+)(?:ULL)?$`)
	rawUserReadRE = regexp.MustCompile(`\bbpf_probe_read_user\s*\(`)
	helperMacroRE = regexp.MustCompile(`(?m)^\s*#\s*define\s+bpf_probe_read_user\b`)
)

func readKernelSource(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "kern", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func TestOpenSSLTaggedPointerMask(t *testing.T) {
	header := readKernelSource(t, "openssl_untag.h")
	match := pointerMaskRE.FindStringSubmatch(header)
	if match == nil {
		t.Fatal("OPENSSL_USER_POINTER_MASK is missing or not a hexadecimal constant")
	}
	mask, err := strconv.ParseUint(match[1], 0, 64)
	if err != nil {
		t.Fatalf("parse OPENSSL_USER_POINTER_MASK: %v", err)
	}

	tests := []struct {
		name    string
		pointer uint64
		want    uint64
	}{
		{name: "untagged", pointer: 0x0000006e8853ec8a, want: 0x0000006e8853ec8a},
		{name: "Android TBI tag", pointer: 0xb400006e8853ec8a, want: 0x0000006e8853ec8a},
		{name: "MTE tag", pointer: 0x0a00006e8853ec8a, want: 0x0000006e8853ec8a},
		{name: "highest untagged address", pointer: 0x00ffffffffffffff, want: 0x00ffffffffffffff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pointer & mask; got != tt.want {
				t.Errorf("0x%016x & 0x%016x = 0x%016x, want 0x%016x", tt.pointer, mask, got, tt.want)
			}
		})
	}
}

func TestOpenSSLUserReadsUseExplicitUntaggedHelper(t *testing.T) {
	probeFiles := []string{
		"openssl.h",
		"openssl_masterkey.h",
		"openssl_masterkey_3.0.h",
		"openssl_masterkey_3.2.h",
	}
	for _, name := range probeFiles {
		t.Run(name, func(t *testing.T) {
			source := readKernelSource(t, name)
			if helperMacroRE.MatchString(source) {
				t.Fatal("must not redefine bpf_probe_read_user; call openssl_probe_read_user explicitly")
			}
			if rawUserReadRE.MatchString(source) {
				t.Fatal("raw bpf_probe_read_user call bypasses Android tagged-pointer normalization")
			}
			if !strings.Contains(source, "openssl_probe_read_user(") {
				t.Fatal("expected OpenSSL user-memory reads to use openssl_probe_read_user")
			}
		})
	}

	header := readKernelSource(t, "openssl_untag.h")
	if helperMacroRE.MatchString(header) {
		t.Fatal("openssl_untag.h must not redefine bpf_probe_read_user")
	}
	if got := len(rawUserReadRE.FindAllStringIndex(header, -1)); got != 1 {
		t.Fatalf("openssl_untag.h has %d raw user-memory reads, want exactly the helper implementation", got)
	}
	if !strings.Contains(header, "bpf_probe_read_user(dst, size, openssl_untag_user_pointer(src))") {
		t.Fatal("openssl_probe_read_user must normalize its source pointer before reading user memory")
	}
}
