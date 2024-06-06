// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
)

const (
	ProcContainerCgroupPath = "/proc/1/cgroup"
	ProcContainerSchedPath  = "/proc/1/sched"
)

// CONFIG CHECK ITEMS
var (
	configCheckItems = []string{
		"CONFIG_BPF",
		"CONFIG_UPROBES",
		"CONFIG_ARCH_SUPPORTS_UPROBES",
	}

	configPaths = []string{
		"/proc/config.gz",
		"/boot/config",
		"/boot/config-%s",
		"/lib/modules/%s/build/.config",
	}
)

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

// from internal/btf/bpf.go
// checkKernelBTF attempts to load the raw vmlinux BTF blob at
// /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs.

func checkKernelBTF() (bool, error) {
	_, err := os.Stat(SysKernelBtfVmlinux)

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

	for _, loc := range locations {
		_, err := os.Stat(fmt.Sprintf(loc, release))
		if err != nil {
			continue
		}
		return true, nil
	}
	return false, err
}

func IsEnableBTF() (bool, error) {
	found, e := checkKernelBTF()
	if e == nil && found {
		return true, nil
	}

	var KernelConfig = make(map[string]string)

	KernelConfig, e = GetSystemConfig()
	if e != nil {
		return false, e
	}

	bc, found := KernelConfig[ConfigDebugInfoBtf]
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

// IsEnableBPF check BPF CONFIG
func IsEnableBPF() (bool, error) {
	var e error
	var KernelConfig = make(map[string]string)

	KernelConfig, e = GetSystemConfig()
	if e != nil {
		return false, e
	}

	for _, item := range configCheckItems {
		bc, found := KernelConfig[item]
		if !found {
			// 没有这个配置项
			return false, fmt.Errorf("Config not found,  item:%s.", item)
		}

		//如果有，在判断配置项的值
		if bc != "y" {
			// 没有开启
			return false, fmt.Errorf("Config disabled, item :%s.", item)
		}
	}

	return true, nil
}

// IsContainer returns true if the process is running in a container.
func IsContainer() (bool, error) {
	b, e := isContainerCgroup()
	if e != nil {
		return false, e
	}

	// if b is true, it's a container
	if b {
		return true, nil
	}

	// if b is false, continue to check sched
	b, e = isContainerSched()
	if e != nil {
		return false, e
	}

	return b, nil
}

// isContainerCgroup returns true if the process is running in a container.
// https://www.baeldung.com/linux/is-process-running-inside-container

func isContainerCgroup() (bool, error) {
	var f *os.File
	var err error
	var i int
	f, err = os.Open(ProcContainerCgroupPath)
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

// isContainerSched returns true if the process is running in a container.
// https://man7.org/linux/man-pages/man7/sched.7.html
func isContainerSched() (bool, error) {
	var f *os.File
	var err error
	var i int
	f, err = os.Open(ProcContainerSchedPath)
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
	case strings.Contains(string(b[:i]), "run-on-arch-com (1, #threads"):
		return true, nil
	case strings.Contains(string(b[:i]), "init (1, #threads:"):
		return false, nil
	case strings.Contains(string(b[:i]), "systemd (1, #threads"):
		return false, nil
	}

	return false, nil
}
