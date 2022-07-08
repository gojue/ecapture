//go:build !androidgki
// +build !androidgki

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	SYS_KERNEL_BTF_VMLINUX     = "/sys/kernel/btf/vmlinux"
	CONFIG_DEBUG_INFO_BTF      = "CONFIG_DEBUG_INFO_BTF"
	PROC_CONTAINER_CGROUP_PATH = "/proc/1/cgroup"
	PROC_CONTAINER_SCHED_PATH  = "/proc/1/sched"
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
	var found bool
	i, e := getOSUnamer()
	if e != nil {
		return KernelConfig, e
	}

	for _, system_config_path := range configPaths {
		var bootConf = system_config_path
		if strings.Index(system_config_path, "%s") != -1 {
			bootConf = fmt.Sprintf(system_config_path, i.Release)
		}

		KernelConfig, e = getLinuxConfig(bootConf)
		if e != nil {
			// 没有找到配置文件，继续找下一个
			continue
		}

		if len(KernelConfig) > 0 {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("KernelConfig not found.")
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
	if err = parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}

// IsContainer returns true if the process is running in a container.
func IsContainer() (bool, error) {
	b, e := isCOntainerCgroup()
	if e != nil {
		return false, e
	}

	// if b is false, continue to check /proc/1/sched
	if b {
		b, e = isCOntainerSched()
		if e != nil {
			return false, e
		}

		return b, nil
	}

	return b, nil
}

// isCOntainerCgroup returns true if the process is running in a container.
// https://www.baeldung.com/linux/is-process-running-inside-container

func isCOntainerCgroup() (bool, error) {
	var f *os.File
	var err error
	var i int
	f, err = os.Open(PROC_CONTAINER_CGROUP_PATH)
	if err != nil {
		return false, err
	}
	defer f.Close()
	b := make([]byte, 1024)
	i, err = f.Read(b)
	if err != nil {
		return false, err
	}
	switch {
	case strings.Contains(string(b[:i]), "cpuset:/docker"):
		// CGROUP V1 docker container
		return true, nil
	case strings.Contains(string(b[:i]), "cpuset:/kubepods"):
		// k8s container
		return true, nil
	case strings.Contains(string(b[:i]), "0::/\n"):
		// CGROUP V2 docker container
		return true, nil
	}

	return false, nil
}

// isCOntainerSched returns true if the process is running in a container.
// https://man7.org/linux/man-pages/man7/sched.7.html
func isCOntainerSched() (bool, error) {
	var f *os.File
	var err error
	var i int
	f, err = os.Open(PROC_CONTAINER_SCHED_PATH)
	if err != nil {
		return false, err
	}
	defer f.Close()
	b := make([]byte, 1024)
	i, err = f.Read(b)
	if err != nil {
		return false, err
	}
	switch {
	case strings.Contains(string(b[:i]), "bash (1, #threads"):
		return true, nil
	}
	return false, nil
}
