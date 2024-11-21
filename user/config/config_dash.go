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
	"fmt"
	"os"
	"strings"
)

// DashConfig Dashpath 与 readline 两个参数，使用时二选一
type DashConfig struct {
	BaseConfig
	Dashpath         string `json:"dashpath"` //dash的文件路径
	Readline         string `json:"readline"`
	ErrNo            int
	ElfType          uint8 //
	ReadlineFuncName string
}

func NewDashConfig() *DashConfig {
	config := &DashConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (bc *DashConfig) Check() error {
	var binaryPath string
	switch bc.ElfType {
	case ElfTypeBin:
		binaryPath = bc.Dashpath
	case ElfTypeSo:
		binaryPath = bc.Readline
	default:
		binaryPath = "/bin/dash"
	}

	file, err := elf.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	symbols, err := file.DynamicSymbols()
	if err != nil {
		return err
	}

	bc.ReadlineFuncName = "read"

	targetSymbol := "read"
	for _, sym := range symbols {
		if sym.Name == targetSymbol {
			return nil
		}
	}

	return fmt.Errorf("symbol [%s] not found in [%s]", targetSymbol, binaryPath)
}

func (bc *DashConfig) checkElf() error {
	// 如果readline 配置，且存在，则直接返回。
	if bc.Readline != "" || len(strings.TrimSpace(bc.Readline)) > 0 {
		_, e := os.Stat(bc.Readline)
		if e != nil {
			return e
		}
		bc.ElfType = ElfTypeSo
		return nil
	}

	//如果配置 dash的地址，且存在，则直接返回
	if bc.Dashpath != "" || len(strings.TrimSpace(bc.Dashpath)) > 0 {
		_, e := os.Stat(bc.Dashpath)
		if e != nil {
			return e
		}
		bc.ElfType = ElfTypeBin
		return nil
	}

	//如果没配置，则自动查找。
	dash, b := os.LookupEnv("SHELL")
	if b {
		soPath, e := getDynPathByElf(dash, "libreadline.so")
		if e != nil {
			bc.Dashpath = dash
			bc.ElfType = ElfTypeBin
		} else {
			bc.Dashpath = soPath
			bc.ElfType = ElfTypeSo
		}

	} else {
		return errors.New("cant found $SHELL path.")
	}
	return nil
}

func (bc *DashConfig) Bytes() []byte {
	b, e := json.Marshal(bc)
	if e != nil {
		return []byte{}
	}
	return b
}
