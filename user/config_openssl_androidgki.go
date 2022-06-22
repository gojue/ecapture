//go:build androidgki
// +build androidgki

package user

import (
	"os"
	"strings"
)

const (
	DEFAULT_OPENSSL_PATH = "/apex/com.android.conscrypt/lib64/libssl.so"
	DEFAULT_LIBC_PATH    = "/apex/com.android.runtime/lib64/bionic/libc.so"
)

func (this *OpensslConfig) Check() error {
	// 如果readline 配置，且存在，则直接返回。
	if this.Openssl != "" || len(strings.TrimSpace(this.Openssl)) > 0 {
		_, e := os.Stat(this.Openssl)
		if e != nil {
			return e
		}
		this.elfType = ELF_TYPE_SO
	} else {
		this.elfType = ELF_TYPE_SO
		this.Openssl = DEFAULT_OPENSSL_PATH
	}

	if this.Pthread != "" || len(strings.TrimSpace(this.Pthread)) > 0 {
		_, e := os.Stat(this.Pthread)
		if e != nil {
			return e
		}
	} else {
		this.Pthread = DEFAULT_LIBC_PATH
	}

	return nil
}
