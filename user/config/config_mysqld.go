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
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type MysqldType uint8

const (
	MysqldTypeUnknow MysqldType = iota
	MysqldType56
	MysqldType57
	MysqldType80
)

// 最终使用mysqld参数
type MysqldConfig struct {
	eConfig
	Mysqldpath  string     `json:"mysqldPath"` //curl的文件路径
	FuncName    string     `json:"funcName"`
	Offset      uint64     `json:"offset"`
	ElfType     uint8      //
	Version     MysqldType //
	VersionInfo string     // info
}

func NewMysqldConfig() *MysqldConfig {
	config := &MysqldConfig{}
	return config
}

func (mc *MysqldConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if mc.Mysqldpath == "" || len(strings.TrimSpace(mc.Mysqldpath)) <= 0 {
		return errors.New("Mysqld path cant be null.")
	}

	_, e := os.Stat(mc.Mysqldpath)
	if e != nil {
		return e
	}
	mc.ElfType = ElfTypeBin

	//如果配置 funcname ，则使用用户指定的函数名
	if mc.FuncName != "" || len(strings.TrimSpace(mc.FuncName)) > 0 {
		return nil
	}

	//如果配置 Offset ，则使用用户指定的Offset
	if mc.Offset > 0 {
		mc.FuncName = "[_IGNORE_]"
		return nil
	}

	//r, _ := regexp.Compile("^(?:# *)?(CONFIG_\\w*)(?:=| )(y|n|m|is not set|\\d+|0x.+|\".*\")$")
	_elf, e := elf.Open(mc.Mysqldpath)
	if e != nil {
		return e
	}

	dynamicSymbols, err := _elf.DynamicSymbols()
	if err != nil {
		return err
	}

	// _Z16dispatch_command19enum_server_commandP3THDPcjbb

	r, _ := regexp.Compile(`\w+dispatch_command\w+`)
	funcName := ""
	for _, sym := range dynamicSymbols {
		match := r.FindStringSubmatch(sym.Name)
		if match == nil {
			continue
		}
		//fmt.Printf("\tsize:%d,  name:%s,  offset:%d\n", sym.Size, sym.Name, 0)
		funcName = sym.Name
		break
	}

	//如果没找到，则报错。
	if funcName == "" {
		return errors.New(fmt.Sprintf("cant match mysql query function to hook with mysqld file::%s", mc.Mysqldpath))
	}

	mc.Version = MysqldType56
	mc.VersionInfo = "mysqld-5.6"

	// 判断mysqld 版本
	found := strings.Contains(funcName, "COM_DATA")
	if found {
		roSection := _elf.Section(".rodata")
		var buf []byte
		buf, e = roSection.Data()
		var ver MysqldType
		var verInfo string
		if e == nil {
			ver, verInfo = getMysqlVer(buf)
		}
		mc.Version = ver
		mc.VersionInfo = verInfo
	}

	mc.FuncName = funcName

	return nil
}

func getMysqlVer(buf []byte) (MysqldType, string) {

	var slice [][]byte

	if slice = bytes.Split(buf, []byte("\x00")); slice == nil {
		return MysqldTypeUnknow, ""
	}

	length := len(slice)
	var offset int

	for i := 0; i < length; i++ {
		if len(slice[i]) == 0 {
			continue
		}

		// mysqld-Version must be less then 50
		//// mysqld-5.7
		l := len(slice[i])
		if l > 15 || l < 8 {
			continue
		}

		mysqldVer := string(slice[i])
		if strings.Contains(mysqldVer, "mysqld-8.") {
			//fmt.Println(fmt.Sprintf("offset:%d, body:%s", offset, slice[i]))
			return MysqldType80, mysqldVer
		} else if strings.Contains(mysqldVer, "mysqld-5.7") {
			return MysqldType57, mysqldVer
		}
		offset += len(slice[i]) + 1
	}
	return MysqldTypeUnknow, ""
}
