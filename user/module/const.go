// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package module

import "runtime"

const (
	ProbeTypeUprobe = "uprobe"
	ProbeTypeKprobe = "kprobe"
	ProbeTypeTC     = "TC"
	ProbeTypeTP     = "tracepoint"
	ProbeTypeXDP    = "XDP"
)

const (
	ModuleNameBash     = "EBPFProbeBash"
	ModuleNameMysqld   = "EBPFProbeMysqld"
	ModuleNamePostgres = "EBPFProbePostgres"
	ModuleNameOpenssl  = "EBPFProbeOPENSSL"
	ModuleNameGnutls   = "EBPFProbeGNUTLS"
	ModuleNameNspr     = "EBPFProbeNSPR"
	ModuleNameGotls    = "EBPFProbeGoTLS"
)

const (
	BashErrnoDefault int = 128
)

const (
	// 备选 HOOK的函数  SSL_is_init_finished \ SSL_get_wbio \ SSL_write
	MasterKeyHookFuncOpenSSL = "SSL_write"

	/*
		在boringSSL类库里，SSL_write函数调用了 SSL_do_handshake ，
		SSL_do_handshake 函数执行时，当前SSL链接握手可能还未完成，且
	*/
	// 2022-12-16 改为 SSL_in_init
	MasterKeyHookFuncBoringSSL = "SSL_in_init"
	MasterKeyHookFuncSSLBefore = "SSL_in_before"
	MasterKeyHookFuncSSLState  = "SSL_state"
)

var (
	/*
	* 为了读取到TLS握手完成后的client_random等密钥，必需要选择一个合适的HOOK函数。
	* SSL_write\SSL_read时，TLS握手是建立完成的，但调用过于频繁，会带来性能问题，参见https://github.com/gojue/ecapture/issues/463
	* 综合来看，合适的HOOK函数需要满足以下几个条件:
	* 1. 函数是在TLS握手完成后调用
	* 2. 函数名在动态链接库的符号表中是导出状态
	* 3. 函数是低频调用
	*
	* 在 openssl 类库中，以客户端角色调用 `SSL_connect` 或者以服务端角色 `SSL_accept` ，最终都会进入 `ssl/statem/statem.c` 的 `state_machine` 函数进行TLS握手。
	* 所以，可选范围是在这个函数内以大写`SSL`开头的函数。
	* 当使用openssl的方式为`同步`调用时，TLS握手成功会返回1，也就是`ret = 1`，即需要在这个变量赋值后，被调用的函数，才能拿到符合要求的内存数据。 `state_machine`函数内符合要求的就只有`SSL_get_wbio`了。
	* 当使用openssl的方式为`异步`调用时，还需要增加`SSL_in_before`函数。
	 */
	masterKeyHookFuncs = []string{
		"SSL_get_wbio", // openssl
		//"SSL_is_init",  // boringssl
		// 备用HOOK 函数
		//"SSL_is_init_finished",
		MasterKeyHookFuncSSLBefore,
		"SSL_do_handshake",
	}
)

var defaultSoPath = "/lib/x86_64-linux-gnu"

func init() {
	if runtime.GOARCH == "arm64" {
		defaultSoPath = "/lib/aarch64-linux-gnu"
	}
}
