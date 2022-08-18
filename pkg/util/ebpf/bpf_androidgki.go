//go:build androidgki
// +build androidgki

package ebpf

import (
	"bufio"
	"compress/gzip"
	"fmt"
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

	// check if the file is gzipped
	var magic []byte
	var i int
	magic = make([]byte, 2)
	i, err = f.Read(magic)
	if err != nil {
		return KernelConfig, err
	}
	if i != 2 {
		return KernelConfig, fmt.Errorf("read %d bytes, expected 2", i)
	}
	_, err = f.Seek(0, 0)
	if err != nil {
		return KernelConfig, err
	}

	var s *bufio.Scanner
	// big-endian magic number for gzip is 0x1f8b
	// little-endian magic number for gzip is 0x8b1f
	if (magic[0] == 0x1f && magic[1] == 0x8b) || (magic[0] == 0x8b && magic[1] == 0x1f) {
		// gzip file
		reader, e := gzip.NewReader(f)
		if e != nil {
			return KernelConfig, err
		}
		s = bufio.NewScanner(reader)
	} else {
		// not gzip file
		s = bufio.NewScanner(f)
	}

	if err = parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}

// IsContainedInCgroup returns true if the process is running in a container.
func IsContainer() (bool, error) {
	return false, nil
}
