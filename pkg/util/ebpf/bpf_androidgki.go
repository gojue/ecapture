//go:build androidgki
// +build androidgki

package ebpf

import (
	"bufio"
	"compress/gzip"
	"os"
)

const (
	BOOT_CONFIG_PATH       = "/proc/config.gz"
	CONFIG_DEBUG_INFO_BTF  = "CONFIG_DEBUG_INFO_BTF"
	SYS_KERNEL_BTF_VMLINUX = "/sys/kernel/btf/vmlinux"
)

var (
	// use same list of locations as libbpf
	// https://android.googlesource.com/platform/external/libbpf/

	locations = []string{
		"/sys/kernel/btf/vmlinux",
	}
)

func GetSystemConfig() (map[string]string, error) {
	return getAndroidConfig(BOOT_CONFIG_PATH)
}

func getAndroidConfig(filename string) (map[string]string, error) {
	var KernelConfig = make(map[string]string)
	// Open file bootConf.
	f, err := os.Open(filename)
	if err != nil {
		return KernelConfig, err
	}
	defer f.Close()

	// uncompress
	reader, err := gzip.NewReader(f)
	if err != nil {
		return KernelConfig, err
	}
	defer reader.Close()

	s := bufio.NewScanner(reader)
	if err = parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}

// IsContainedInCgroup returns true if the process is running in a container.
func IsContainer() (bool, error) {
	return false, nil
}
