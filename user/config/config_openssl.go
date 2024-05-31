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
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

/*
关于CGroup路径问题，可以自己创建，也可以使用系统的。不限制CGroup版本， v1、v2都可以。
ubuntu系统上，默认在/sys/fs/cgroup ，CentOS上，可以自己创建。 代码中已经实现。
或使用如下命令：
创建命令：mkdir /mnt/ecapture_cgroupv2
mount -t cgroup2 none /mnt/ecapture_cgroupv2
*/
const (
	cgroupPath       = "/sys/fs/cgroup"         // ubuntu
	cgroupPathCentos = "/mnt/ecapture_cgroupv2" // centos
)

// 最终使用openssl参数
type OpensslConfig struct {
	BaseConfig
	// Curlpath   string `json:"curlPath"` //curl的文件路径
	Openssl    string `json:"openssl"`
	Model      string `json:"model"`      // eCapture Openssl capture model. text:pcap:keylog
	PcapFile   string `json:"pcapfile"`   // pcapFile  the  raw  packets  to file rather than parsing and printing them out.
	KeylogFile string `json:"keylog"`     // Keylog  The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.
	Ifname     string `json:"ifname"`     // (TC Classifier) Interface name on which the probe will be attached.
	PcapFilter string `json:"pcapfilter"` // pcap filter
	SslVersion string `json:"sslversion"` // openssl version like 1.1.1a/1.1.1f/boringssl_1.1.1
	CGroupPath string `json:"cgrouppath"` // cgroup path, used for filter process
	ElfType    uint8  //
	IsAndroid  bool   //	is Android OS ?
	AndroidVer string // Android OS version
}

func NewOpensslConfig() *OpensslConfig {
	config := &OpensslConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (oc *OpensslConfig) checkModel() string {
	var m string
	switch oc.Model {
	case TlsCaptureModelKeylog, TlsCaptureModelKey:
		m = TlsCaptureModelKey
	case TlsCaptureModelPcap, TlsCaptureModelPcapng:
		m = TlsCaptureModelPcap
	default:
		m = TlsCaptureModelText
	}
	return m
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
		// TODO 判断是否已经mount
		return newPath, nil
	}

	// 若新路径不存在，重新创建
	err = os.Mkdir(newPath, os.FileMode(0o755))
	if err != nil {
		return "", err
	}
	err = syscall.Mount("none", newPath, "cgroup2", 0, "")
	if err != nil {
		return "", err
	}
	return newPath, nil
}

func (oc *OpensslConfig) Bytes() []byte {
	b, e := json.Marshal(oc)
	if e != nil {
		return []byte{}
	}
	return b
}
