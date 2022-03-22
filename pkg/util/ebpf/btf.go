package ebpf

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

const (
	BOOT_CONFIG_PATH   = "/boot/config-%s"
	CONFIG_BTF_TAGNAME = "CONFIG_DEBUG_INFO_BTF"
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

type UnameInfo struct {
	SysName    string
	Nodename   string
	Release    string
	Version    string
	Machine    string
	Domainname string
}

func getOSUnamer() (*UnameInfo, error) {
	u := unix.Utsname{}
	e := unix.Uname(&u)
	if e != nil {
		return nil, e
	}
	ui := UnameInfo{}
	ui.SysName = charsToString(u.Sysname)
	ui.Nodename = charsToString(u.Nodename)
	ui.Release = charsToString(u.Release)
	ui.Version = charsToString(u.Version)
	ui.Machine = charsToString(u.Machine)
	ui.Domainname = charsToString(u.Domainname)

	return &ui, nil
}

func charsToString(ca [65]byte) string {
	s := make([]byte, len(ca))
	var lens int
	for ; lens < len(ca); lens++ {
		if ca[lens] == 0 {
			break
		}
		s[lens] = uint8(ca[lens])
	}
	return string(s[0:lens])
}

// from internal/btf/btf.go
// checkKernelBTF attempts to load the raw vmlinux BTF blob at
// /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs.

func checkKernelBTF() (bool, error) {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")

	// if exist ,return true
	if err == nil {
		return true, nil
	}

	return findVMLinux()
}

// findVMLinux scans multiple well-known paths for vmlinux kernel images.
func findVMLinux() (bool, error) {
	kv, err := getOSUnamer()
	if err != nil {
		return false, err
	}
	release := kv.Release
	// use same list of locations as libbpf
	// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122
	locations := []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}

	for _, loc := range locations {
		_, err := os.Stat(fmt.Sprintf(loc, release))
		if err != nil {
			continue
		}
		return true, nil
	}
	return false, err
}
