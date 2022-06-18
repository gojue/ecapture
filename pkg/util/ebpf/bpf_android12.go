//go:build android12
// +build android12

package ebpf

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
)

const (
	BOOT_CONFIG_PATH             = "/proc/config.gz"
	CONFIG_BTF_TAGNAME           = "CONFIG_DEBUG_INFO_BTF"
	SYS_KERNEL_BTF_VMLINUX       = "/sys/kernel/btf/vmlinux"
	CONFIG_ARCH_SUPPORTS_UPROBES = "CONFIG_ARCH_SUPPORTS_UPROBES"
	CONFIG_UPROBES               = "CONFIG_UPROBES"
)

var (
	// use same list of locations as libbpf
	// https://android.googlesource.com/platform/external/libbpf/

	locations = []string{
		//"/sys/kernel/btf/vmlinux",
	}
)

func IsEnableBTF() (bool, error) {
	found, e := checkKernelBTF()
	if e == nil && found {
		return true, nil
	}

	bootConf := fmt.Sprintf(BOOT_CONFIG_PATH)

	// Open file bootConf.
	f, err := os.Open(bootConf)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// uncompress
	reader, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer reader.Close()

	var KernelConfig = make(map[string]string)
	s := bufio.NewScanner(reader)
	if err := parse(s, KernelConfig); err != nil {
		return false, err
	}
	bc, found := KernelConfig[CONFIG_BTF_TAGNAME]
	if !found {
		// 没有这个配置项
		return false, nil
	}

	//如果有，在判断配置项的值
	if bc != "y" {
		// 没有开启
		return false, nil
	}
	return true, nil
}
