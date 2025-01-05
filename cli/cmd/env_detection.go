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

package cmd

import (
	"fmt"
	"runtime"

	"github.com/gojue/ecapture/pkg/util/kernel"
	"golang.org/x/sys/unix"
)

func detectKernel() error {
	// 系统内核版本检测
	kv, err := kernel.HostVersion()
	if err != nil {
		return fmt.Errorf("failed to get the host kernel version: %v", err)
	}
	switch runtime.GOARCH {
	case "amd64":
		if kv < kernel.VersionCode(4, 18, 0) {
			return fmt.Errorf("the Linux/Android Kernel version %v (x86_64) is not supported. Requires a version greater than 4.18", kv)
		}
	case "arm64":
		if kv < kernel.VersionCode(5, 5, 0) {
			return fmt.Errorf("the Linux/Android Kernel version %v (aarch64) is not supported. Requires a version greater than 5.5", kv)
		}
	default:
		return fmt.Errorf("unsupported CPU arch:%v", runtime.GOARCH)
	}

	return nil
}
func detectBpfCap() error {
	// BPF 权限检测
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData // why 2? pls check https://github.com/golang/go/issues/44312
	err := unix.Capget(&hdr, &data[0])
	if err != nil {
		return fmt.Errorf("failed to get the capabilities of the current process: %v", err)
	}

	capBpfMask := uint32(1 << (unix.CAP_BPF - 32))
	capSysAdminMask := uint32(1 << unix.CAP_SYS_ADMIN)
	haveBpfCap := (data[1].Permitted&capBpfMask != 0) || (data[0].Permitted&capSysAdminMask != 0)
	if !haveBpfCap {
		return fmt.Errorf("the current user does not have CAP_BPF to load bpf programs. Please run as root or use sudo or add the --privileged=true flag for Docker")
	}

	return nil
}

func detectEnv() error {
	// 环境检测

	if err := detectKernel(); err != nil {
		return err
	}

	if err := detectBpfCap(); err != nil {
		return err
	}

	return nil
}
