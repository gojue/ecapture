//go:build !androidgki
// +build !androidgki

// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"fmt"
	"os"
	"strings"
)

// ZshConfig
type ZshConfig struct {
	BaseConfig
	Zshpath          string `json:"zshpath"` //zsh的文件路径
	ErrNo            int
	ElfType          uint8 //
	ReadlineFuncName string
}

func NewZshConfig() *ZshConfig {
	config := &ZshConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (zc *ZshConfig) Check() error {
	var binaryPath string
	switch zc.ElfType {
	case ElfTypeBin:
		binaryPath = zc.Zshpath
	default:
		binaryPath = "/bin/zsh"
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

	zc.ReadlineFuncName = "zleentry"

	targetSymbol := "zleentry"
	for _, sym := range symbols {
		if sym.Name == targetSymbol {
			return nil
		}
	}

	return fmt.Errorf("symbol [%s] not found in [%s]", targetSymbol, binaryPath)
}

func (zc *ZshConfig) checkElf() error {
	//如果配置 zsh的地址，且存在，则直接返回
	if zc.Zshpath != "" || len(strings.TrimSpace(zc.Zshpath)) > 0 {
		_, e := os.Stat(zc.Zshpath)
		if e != nil {
			return e
		}
		zc.ElfType = ElfTypeBin
		return nil
	}

	return nil
}

func (zc *ZshConfig) Bytes() []byte {
	b, e := json.Marshal(zc)
	if e != nil {
		return []byte{}
	}
	return b
}
