//go:build androidgki
// +build androidgki

package user

import (
	"os"
	"strings"
)

const DEFAULT_NSPR_NSS_PATH = "/apex/com.android.conscrypt/lib64/libnspr4.so"

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

	this.Nsprpath = DEFAULT_NSPR_NSS_PATH
	this.elfType = ELF_TYPE_SO

	return nil
}
