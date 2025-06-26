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
	"debug/elf"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

const fallbackBashPath = "/bin/bash"

// BashConfig Bashpath 与 readline 两个参数，使用时二选一
type BashConfig struct {
	BaseConfig
	Bashpath         string `json:"bashpath"` //bash的文件路径
	Readline         string `json:"readline"`
	ErrNo            int
	ElfType          uint8 //
	ReadlineFuncName string
}

func NewBashConfig() *BashConfig {
	config := &BashConfig{}

	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (bc *BashConfig) Check() error {
	err := bc.checkElf()
	if err != nil {
		return err
	}
	var binaryPath string
	switch bc.ElfType {
	case ElfTypeBin:
		binaryPath = bc.Bashpath
	case ElfTypeSo:
		binaryPath = bc.Readline
	default:
		binaryPath = "/bin/bash"
	}

	file, err := elf.Open(binaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	symbols, err := file.DynamicSymbols()
	if err != nil {
		return err
	}

	targetSymbol := "readline_internal_teardown"
	found := false
	for _, sym := range symbols {
		if sym.Name == targetSymbol {
			found = true
			break
		}
	}
	if found {
		bc.ReadlineFuncName = "readline_internal_teardown"
	} else {
		bc.ReadlineFuncName = "readline"
	}
	return nil
}

func (bc *BashConfig) checkElf() error {
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
	if b && strings.Contains(bash, "bash") {
		bc.Bashpath = bash
		soPath, e := getDynPathByElf(bash, "libreadline.so")
		if e != nil {
			bc.ElfType = ElfTypeBin
		} else {
			bc.Readline = soPath
			bc.ElfType = ElfTypeSo
		}
	} else if _, err := os.Stat(fallbackBashPath); err == nil {
		bc.Bashpath = fallbackBashPath
		soPath, e := getDynPathByElf(fallbackBashPath, "libreadline.so")
		if e != nil {
			bc.ElfType = ElfTypeBin
		} else {
			bc.Readline = soPath
			bc.ElfType = ElfTypeSo
		}
	} else {
		return errors.New("cant find valid bash path in $PATH and /bin/bash")
	}
	return nil
}

func (bc *BashConfig) Bytes() []byte {
	b, e := json.Marshal(bc)
	if e != nil {
		return []byte{}
	}
	return b
}
