/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import (
	"os"
	"strings"
)

// 最终使用openssl参数
type NsprConfig struct {
	eConfig
	Firefoxpath string `json:"firefoxpath"` //curl的文件路径
	Nsprpath    string `json:"nsprpath"`
	elfType     uint8  //
}

func NewNsprConfig() *NsprConfig {
	config := &NsprConfig{}
	return config
}

func (this *NsprConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Nsprpath != "" || len(strings.TrimSpace(this.Nsprpath)) > 0 {
		_, e := os.Stat(this.Nsprpath)
		if e != nil {
			return e
		}
		this.elfType = ELF_TYPE_SO
		return nil
	}

	//如果配置 Curlpath的地址，判断文件是否存在，不存在则直接返回
	if this.Firefoxpath != "" || len(strings.TrimSpace(this.Firefoxpath)) > 0 {
		_, e := os.Stat(this.Firefoxpath)
		if e != nil {
			return e
		}
	} else {
		//如果没配置，则直接指定。
		this.Nsprpath = "/usr/lib/firefox/firefox"
	}

	soPath, e := getDynPathByElf(this.Nsprpath, "libnspr4.so")
	if e != nil {
		//this.logger.Printf("get bash:%s dynamic library error:%v.\n", bash, e)
		this.Nsprpath = "/lib/x86_64-linux-gnu/libnspr4.so"
		//this.Gnutls = "/usr/lib/firefox/libnss3.so"
		//"/usr/lib/firefox/libnspr4.so"
		this.elfType = ELF_TYPE_SO
		_, e = os.Stat(this.Nsprpath)
		if e != nil {
			return e
		}
		return nil
	}

	this.Nsprpath = soPath
	this.elfType = ELF_TYPE_SO

	return nil
}
