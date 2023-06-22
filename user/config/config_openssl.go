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

package config

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

/*
关于CGroup路径问题，可以自己创建，也可以使用系统的。不限制CGroup版本， v1、v2都可以。
ubuntu系统上，默认在/sys/fs/cgroup ，CentOS上，可以自己创建。 代码中已经实现。
或使用如下命令：
创建命令：mkdir /mnt/ecapture_cgroupv2
mount -t cgroup2 none /mnt/ecapture_cgroupv2
*/
const cgroupPath = "/sys/fs/cgroup"               // ubuntu
const cgroupPathCentos = "/mnt/ecapture_cgroupv2" // centos

// 最终使用openssl参数
type OpensslConfig struct {
	eConfig
	Curlpath string `json:"curlPath"` //curl的文件路径
	Openssl  string `json:"openssl"`
	//Pthread    string `json:"pThread"`    // /lib/x86_64-linux-gnu/libpthread.so.0
	Write      string `json:"write"`      // Write  the  raw  packets  to file rather than parsing and printing them out.
	Ifname     string `json:"ifName"`     // (TC Classifier) Interface name on which the probe will be attached.
	Port       uint16 `json:"port"`       // capture port
	SslVersion string `json:"sslVersion"` // openssl version like 1.1.1a/1.1.1f/boringssl_1.1.1
	CGroupPath string `json:"CGroupPath"` // cgroup path, used for filter process
	ElfType    uint8  //
	IsAndroid  bool   //	is Android OS ?
}

func NewOpensslConfig() *OpensslConfig {
	config := &OpensslConfig{}
	return config
}

func checkCgroupPath(cp string) (string, error) {
	var st syscall.Statfs_t
	err := syscall.Statfs(cp, &st)
	if err != nil {
		return "", err
	}
	newPath := cp
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		newPath = filepath.Join(cgroupPath, "unified")
	}

	// 判断老路径是否存在，正常的返回
	err = syscall.Statfs(newPath, &st)
	if err == nil {
		return newPath, nil
	}

	// 若老路径不存在，则改用新路径
	// for CentOS
	newPath = cgroupPathCentos
	err = syscall.Statfs(newPath, &st)
	if err == nil {
		//TODO 判断是否已经mount
		return newPath, nil
	}

	// 若新路径不存在，重新创建
	err = os.Mkdir(newPath, os.FileMode(0755))
	if err != nil {
		return "", err
	}
	err = syscall.Mount("none", newPath, "cgroup2", 0, "")
	if err != nil {
		return "", err
	}
	return newPath, nil
}
