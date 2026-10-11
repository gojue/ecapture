package cmd

import (
	"testing"

	"github.com/gojue/ecapture/v2/pkg/util/kernel"
)

func TestMinimumKernelVersion(t *testing.T) {
	tests := []struct {
		goarch string
		want   kernel.Version
		name   string
	}{
		{goarch: "amd64", want: kernel.VersionCode(4, 18, 0), name: "x86_64"},
		{goarch: "arm64", want: kernel.VersionCode(5, 5, 0), name: "aarch64"},
		{goarch: "loong64", want: kernel.VersionCode(6, 6, 0), name: "loongarch64"},
	}
	for _, tt := range tests {
		t.Run(tt.goarch, func(t *testing.T) {
			got, name, err := minimumKernelVersion(tt.goarch)
			if err != nil {
				t.Fatalf("minimumKernelVersion(%q): %v", tt.goarch, err)
			}
			if got != tt.want || name != tt.name {
				t.Fatalf("minimumKernelVersion(%q) = (%v, %q), want (%v, %q)", tt.goarch, got, name, tt.want, tt.name)
			}
		})
	}
	if _, _, err := minimumKernelVersion("mips64"); err == nil {
		t.Fatal("unsupported architecture did not return an error")
	}
}
