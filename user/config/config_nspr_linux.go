//go:build !androidgki
// +build !androidgki

/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package config

import (
	"os"
	"path/filepath"
	"strings"

	"errors"
)

func (this *NsprConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Nsprpath != "" || len(strings.TrimSpace(this.Nsprpath)) > 0 {
		_, e := os.Stat(this.Nsprpath)
		if e != nil {
			return e
		}
		this.ElfType = ELF_TYPE_SO
		return nil
	}

	if this.NoSearch {
		return errors.New("NoSearch requires specifying lib path")
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if this.Firefoxpath != "" || len(strings.TrimSpace(this.Firefoxpath)) > 0 {
		_, e := os.Stat(this.Firefoxpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		this.Firefoxpath = "/usr/lib/firefox/firefox"
	}

	soPath, e := getDynPathByElf(this.Firefoxpath, "libnspr4.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86_BINARY_PREFIX)
		prefix := X86_BINARY_PREFIX
		if e != nil {
			prefix = OTHERS_BINARY_PREFIX
		}
		this.Nsprpath = filepath.Join(prefix, "libnspr4.so")
		//this.Gnutls = "/usr/lib/firefox/libnss3.so"
		//"/usr/lib/firefox/libnspr4.so"
		this.ElfType = ELF_TYPE_SO
		_, e = os.Stat(this.Nsprpath)
		if e != nil {
			return e
		}
		return nil
	}

	this.Nsprpath = soPath
	this.ElfType = ELF_TYPE_SO

	return nil
}
