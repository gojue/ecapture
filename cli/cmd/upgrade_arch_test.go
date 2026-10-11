package cmd

import "testing"

func TestReleaseArch(t *testing.T) {
	for machine, want := range map[string]string{
		"x86_64":      "amd64",
		"aarch64":     "arm64",
		"loongarch64": "loong64",
	} {
		got, err := releaseArch(machine)
		if err != nil {
			t.Fatalf("releaseArch(%q): %v", machine, err)
		}
		if got != want {
			t.Fatalf("releaseArch(%q) = %q, want %q", machine, got, want)
		}
	}
	if _, err := releaseArch("mips64"); err == nil {
		t.Fatal("unsupported release architecture did not return an error")
	}
}
