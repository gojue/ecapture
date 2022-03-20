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

/*
type Utsname struct {
	Sysname    [65]byte
	Nodename   [65]byte
	Release    [65]byte
	Version    [65]byte
	Machine    [65]byte
	Domainname [65]byte
}
*/

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
