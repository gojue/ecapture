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
	"strings"
)

// Bashpath 与 readline 两个参数，使用时二选一
type BashConfig struct {
	eConfig
	Bashpath string `json:"bashpath"` //bash的文件路径
	Readline string `json:"readline"`
	ErrNo    int
	ElfType  uint8 //
}

func NewBashConfig() *BashConfig {
	config := &BashConfig{}
	return config
}

func (bc *BashConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if bc.Readline != "" || len(strings.TrimSpace(bc.Readline)) > 0 {
		_, e := os.Stat(bc.Readline)
		if e != nil {
			return e
		}
		bc.ElfType = ElfTypeSo
		return nil
	}

	//如果配置 bash的地址，且存在，则直接返回
	if bc.Bashpath != "" || len(strings.TrimSpace(bc.Bashpath)) > 0 {
		_, e := os.Stat(bc.Bashpath)
		if e != nil {
			return e
		}
		bc.ElfType = ElfTypeBin
		return nil
	}

	//如果没配置，则自动查找。
	bash, b := os.LookupEnv("SHELL")
	if b {
		soPath, e := getDynPathByElf(bash, "libreadline.so")
		if e != nil {
			//bc.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
			bc.Bashpath = bash
			bc.ElfType = ElfTypeBin
		} else {
			bc.Bashpath = soPath
			bc.ElfType = ElfTypeSo
		}

	} else {
		return errors.New("cant found $SHELL path.")
	}

	return nil
}
