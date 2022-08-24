//go:build androidgki
// +build androidgki

/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package config

import (
	"os"
	"strings"
)

const DEFAULT_GNUTLS_PATH = "/apex/com.android.conscrypt/lib64/libgnutls"

func (this *GnutlsConfig) Check() error {

	// 如果readline 配置，且存在，则直接返回。
	if this.Gnutls != "" || len(strings.TrimSpace(this.Gnutls)) > 0 {
		_, e := os.Stat(this.Gnutls)
		if e != nil {
			return e
		}
		this.ElfType = ELF_TYPE_SO
		return nil
	}

	this.Gnutls = DEFAULT_GNUTLS_PATH
	this.ElfType = ELF_TYPE_SO

	return nil
}
