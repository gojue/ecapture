/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"debug/elf"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"regexp"
	"strings"
)

type MYSQLD_TYPE uint8

const (
	MYSQLD_TYPE_56 MYSQLD_TYPE = 0
	MYSQLD_TYPE_57 MYSQLD_TYPE = 1
	MYSQLD_TYPE_80 MYSQLD_TYPE = 2
)

// 最终使用mysqld参数
type MysqldConfig struct {
	eConfig
	Mysqldpath string      `json:"mysqldPath"` //curl的文件路径
	FuncName   string      `json:"funcName"`
	Offset     uint64      `json:"offset"`
	elfType    uint8       //
	version    MYSQLD_TYPE //
}

func NewMysqldConfig() *MysqldConfig {
	config := &MysqldConfig{}
	return config
}

func (this *MysqldConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Mysqldpath == "" || len(strings.TrimSpace(this.Mysqldpath)) <= 0 {
		return errors.New("Mysqld path cant be null.")
	}

	_, e := os.Stat(this.Mysqldpath)
	if e != nil {
		return e
	}
	this.elfType = ELF_TYPE_BIN

	//如果配置 funcname ，则使用用户指定的函数名
	if this.FuncName != "" || len(strings.TrimSpace(this.FuncName)) > 0 {
		return nil
	}

	//如果配置 Offset ，则使用用户指定的Offset
	if this.Offset > 0 {
		this.FuncName = "[_NONEED_]"
		return nil
	}

	//r, _ := regexp.Compile("^(?:# *)?(CONFIG_\\w*)(?:=| )(y|n|m|is not set|\\d+|0x.+|\".*\")$")
	_elf, e := elf.Open(this.Mysqldpath)
	if e != nil {
		return e
	}

	dynamicSymbols, err := _elf.DynamicSymbols()
	if err != nil {
		return err
	}

	// _Z16dispatch_command19enum_server_commandP3THDPcjbb

	r, _ := regexp.Compile("\\w+dispatch_command\\w+")
	funcName := ""
	for _, sym := range dynamicSymbols {
		match := r.FindStringSubmatch(sym.Name)
		if match == nil {
			continue
		}
		//fmt.Printf("\tsize:%d,  name:%s,  offset:%d\n", sym.Size, sym.Name, 0)
		funcName = sym.Name
	}

	//如果没找到，则报错。
	if funcName == "" {
		return errors.New(fmt.Sprintf("cant match mysql query function to hook with mysqld file::%s", this.Mysqldpath))
	}

	this.version = MYSQLD_TYPE_56

	// 判断mysqld 版本
	found := strings.Contains(funcName, "COM_DATA")
	if found {
		this.version = MYSQLD_TYPE_80 // TODO
	}

	this.FuncName = funcName

	// TODO offset
	return nil
}
