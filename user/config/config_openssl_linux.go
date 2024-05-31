//go:build !androidgki
// +build !androidgki

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
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultIfname = "eth0"
)

var (
	libsslSharedObjects = []string{
		"libssl.so.3",   // ubuntu server 22.04
		"libssl.so.1.1", // ubuntu server 21.04
	}
)

func (oc *OpensslConfig) checkOpenssl() error {
	var e error
	var sslPath string
	var soLoadPaths = GetDynLibDirs()
	for _, soPath := range soLoadPaths {
		_, e = os.Stat(soPath)
		if e != nil {
			continue
		}
		//	ubuntu 21.04	libssl.so.1.1   default
		for _, soFile := range libsslSharedObjects {
			sslPath = filepath.Join(soPath, soFile)
			_, e = os.Stat(sslPath)
			if e != nil {
				continue
			}
			oc.Openssl = sslPath
			break
		}
	}
	if oc.Openssl == "" {
		return errors.New("cant found openssl so load path")
	}
	oc.ElfType = ElfTypeSo
	_, e = os.Stat(oc.Openssl)
	if e != nil {
		return e
	}
	return nil
}

func (oc *OpensslConfig) Check() error {
	oc.IsAndroid = false
	var checkedOpenssl bool
	// 如果readline 配置，且存在，则直接返回。
	if oc.Openssl != "" || len(strings.TrimSpace(oc.Openssl)) > 0 {
		_, e := os.Stat(oc.Openssl)
		if e != nil {
			return e
		}
		oc.ElfType = ElfTypeSo
		checkedOpenssl = true
	}

	if oc.Ifname == "" || len(strings.TrimSpace(oc.Ifname)) == 0 {
		oc.Ifname = DefaultIfname
	}

	if checkedOpenssl {
		return nil
	}

	e := oc.checkOpenssl()
	if e != nil {
		return e
	}

	s, e := checkCgroupPath(oc.CGroupPath)
	if e != nil {
		return e
	}
	oc.CGroupPath = s

	oc.Model = oc.checkModel()
	return nil
}
