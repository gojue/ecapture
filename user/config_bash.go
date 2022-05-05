/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

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
	ErrNo	 int
	elfType  uint8  //
}

func NewBashConfig() *BashConfig {
	config := &BashConfig{}
	return config
}

func (this *BashConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Readline != "" || len(strings.TrimSpace(this.Readline)) > 0 {
		_, e := os.Stat(this.Readline)
		if e != nil {
			return e
		}
		this.elfType = ELF_TYPE_SO
		return nil
	}

	//如果配置 bash的地址，且存在，则直接返回
	if this.Bashpath != "" || len(strings.TrimSpace(this.Bashpath)) > 0 {
		_, e := os.Stat(this.Bashpath)
		if e != nil {
			return e
		}
		this.elfType = ELF_TYPE_BIN
		return nil
	}

	//如果没配置，则自动查找。
	bash, b := os.LookupEnv("SHELL")
	if b {
		soPath, e := getDynPathByElf(bash, "libreadline.so")
		if e != nil {
			//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
			this.Bashpath = bash
			this.elfType = ELF_TYPE_BIN
		} else {
			this.Bashpath = soPath
			this.elfType = ELF_TYPE_SO
		}

	} else {
		return errors.New("cant found $SHELL path.")
	}

	return nil
}
