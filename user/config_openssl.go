/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
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

	// 如果readline 配置，且存在，则直接返回。
	if this.Openssl != "" || len(strings.TrimSpace(this.Openssl)) > 0 {
		_, e := os.Stat(this.Openssl)
		if e != nil {
			return e
		}
		this.elfType = ELF_TYPE_SO
		return nil
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

	// find /lib/x86_64-linux-gnu/libpthread.so.0 path
	pthreadSoPath, e := getDynPathByElf(this.Curlpath, "libpthread.so")
	if e != nil {
		_, e = os.Stat(X86_BINARY_PREFIX)
		prefix := X86_BINARY_PREFIX
		if e != nil {
			prefix = OTHERS_BINARY_PREFIX
		}
		this.Pthread = filepath.Join(prefix, "libpthread.so.0")
		_, e = os.Stat(this.Pthread)
		if e != nil {
			return e
		}
	} else {
		this.Pthread = pthreadSoPath
	}
	return nil
}
