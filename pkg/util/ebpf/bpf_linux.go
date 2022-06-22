//go:build !androidgki
// +build !androidgki

package ebpf

import (
	"bufio"
	"fmt"
	"os"
)

const (
	SYS_KERNEL_BTF_VMLINUX = "/sys/kernel/btf/vmlinux"
	CONFIG_DEBUG_INFO_BTF  = "CONFIG_DEBUG_INFO_BTF"
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

	configPaths = []string{
		"/proc/config.gz",
		"/boot/config",
		"/boot/config-%s",
	}
)

func GetSystemConfig() (map[string]string, error) {
	var KernelConfig = make(map[string]string)

	i, e := getOSUnamer()
	if e != nil {
		return KernelConfig, e
	}

	for _, system_config_path := range configPaths {
		bootConf := fmt.Sprintf(system_config_path, i.Release)
		KernelConfig, e = getLinuxConfig(bootConf)
		if e != nil {
			continue
		}

		if len(KernelConfig) > 0 {
			break
		}
	}

	return KernelConfig, nil
}

func getLinuxConfig(filename string) (map[string]string, error) {
	var KernelConfig = make(map[string]string)

	// Open file bootConf.
	f, err := os.Open(filename)
	if err != nil {
		return KernelConfig, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	if err := parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}
