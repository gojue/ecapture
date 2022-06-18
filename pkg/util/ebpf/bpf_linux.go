//go:build !android12
// +build !android12

package ebpf

import (
	"bufio"
	"fmt"
	"os"
)

const (
	BOOT_CONFIG_PATH             = "/boot/config-%s"
	CONFIG_BTF_TAGNAME           = "CONFIG_DEBUG_INFO_BTF"
	SYS_KERNEL_BTF_VMLINUX       = "/sys/kernel/btf/vmlinux"
	CONFIG_ARCH_SUPPORTS_UPROBES = "CONFIG_ARCH_SUPPORTS_UPROBES"
	CONFIG_UPROBES               = "CONFIG_UPROBES"
)

var (
	// use same list of locations as libbpf
	// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122

	locations = []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}
)

func IsEnableBTF() (bool, error) {
	found, e := checkKernelBTF()
	if e == nil && found {
		return true, nil
	}

	i, e := getOSUnamer()
	if e != nil {
		return false, e
	}
	bootConf := fmt.Sprintf(BOOT_CONFIG_PATH, i.Release)

	// Open file bootConf.
	f, err := os.Open(bootConf)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var KernelConfig = make(map[string]string)
	s := bufio.NewScanner(f)
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
