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
type GnutlsConfig struct {
	eConfig
	Curlpath string `json:"curlpath"` //curl的文件路径
	Gnutls   string `json:"gnutls"`
	elfType  uint8  //
}

func NewGnutlsConfig() *GnutlsConfig {
	config := &GnutlsConfig{}
	return config
}

func (this *GnutlsConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Gnutls != "" || len(strings.TrimSpace(this.Gnutls)) > 0 {
		_, e := os.Stat(this.Gnutls)
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
		this.Curlpath = "/usr/bin/wget"
	}

	soPath, e := getDynPathByElf(this.Curlpath, "libgnutls.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		_, e = os.Stat(X86_BINARY_PREFIX)
		prefix := X86_BINARY_PREFIX
		if e != nil {
			prefix = OTHERS_BINARY_PREFIX
		}
		this.Gnutls = filepath.Join(prefix, "libgnutls.so.30")
		this.elfType = ELF_TYPE_SO
		_, e = os.Stat(this.Gnutls)
		if e != nil {
			return e
		}
		return nil
	}

	this.Gnutls = soPath
	this.elfType = ELF_TYPE_SO

	return nil
}
