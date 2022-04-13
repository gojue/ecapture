/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 最终使用openssl参数
type OpensslConfig struct {
	eConfig
	Curlpath string `json:"curlpath"` //curl的文件路径
	Openssl  string `json:"openssl"`
	Pthread  string `json:"pthread"` // /lib/x86_64-linux-gnu/libpthread.so.0
	elfType  uint8  //
}

func NewOpensslConfig() *OpensslConfig {
	config := &OpensslConfig{}
	return config
}

func (this *OpensslConfig) Check() error {

	var checkedOpenssl, checkedConnect bool
	// 如果readline 配置，且存在，则直接返回。
	if this.Openssl != "" || len(strings.TrimSpace(this.Openssl)) > 0 {
		_, e := os.Stat(this.Openssl)
		if e != nil {
			return e
		}
		this.elfType = ELF_TYPE_SO
		checkedOpenssl = true
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if this.Curlpath != "" || len(strings.TrimSpace(this.Curlpath)) > 0 {
		_, e := os.Stat(this.Curlpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		this.Curlpath = "/usr/bin/curl"
	}

	if this.Pthread != "" || len(strings.TrimSpace(this.Pthread)) > 0 {
		_, e := os.Stat(this.Pthread)
		if e != nil {
			return e
		}
		checkedConnect = true
	}

	if checkedConnect && checkedOpenssl {
		return nil
	}

	if !checkedOpenssl {
		e := this.checkOpenssl()
		if e != nil {
			return e
		}
	}

	if !checkedConnect {
		return this.checkConnect()
	}
	return nil
}

func (this *OpensslConfig) checkOpenssl() error {
	soPath, e := getDynPathByElf(this.Curlpath, "libssl.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86_BINARY_PREFIX)
		prefix := X86_BINARY_PREFIX
		if e != nil {
			prefix = OTHERS_BINARY_PREFIX
		}
		this.Openssl = filepath.Join(prefix, "libssl.so.1.1")
		this.elfType = ELF_TYPE_SO
		_, e = os.Stat(this.Openssl)
		if e != nil {
			return e
		}
	} else {
		this.Openssl = soPath
		this.elfType = ELF_TYPE_SO
	}
	return nil
}

func (this *OpensslConfig) checkConnect() error {
	var sharedObjects = []string{
		"libpthread.so.0", // ubuntu 21.04 server
		"libc.so.6",       // ubuntu 21.10 server
	}

	var funcName = ""
	var found bool
	for _, so := range sharedObjects {
		pthreadSoPath, e := getDynPathByElf(this.Curlpath, so)
		if e != nil {
			_, e = os.Stat(X86_BINARY_PREFIX)
			prefix := X86_BINARY_PREFIX
			if e != nil {
				prefix = OTHERS_BINARY_PREFIX
			}
			this.Pthread = filepath.Join(prefix, so)
			_, e = os.Stat(this.Pthread)
			if e != nil {
				return e
			}
		} else {
			this.Pthread = pthreadSoPath
		}

		_elf, e := elf.Open(this.Pthread)
		if e != nil {
			return e
		}

		dynamicSymbols, err := _elf.DynamicSymbols()
		if err != nil {
			return err
		}

		//
		for _, sym := range dynamicSymbols {
			if sym.Name != "connect" {
				continue
			}
			//fmt.Printf("\tsize:%d,  name:%s,  offset:%d\n", sym.Size, sym.Name, 0)
			funcName = sym.Name
			found = true
			break
		}

		// if found
		if found && funcName != "" {
			break
		}
	}

	//如果没找到，则报错。
	if !found || funcName == "" {
		return errors.New(fmt.Sprintf("cant found 'connect' function to hook in files::%v", sharedObjects))
	}
	return nil
}
