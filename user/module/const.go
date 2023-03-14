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
	MasterKeyHookFuncOpenSSL = "SSL_write"

	/*
		在boringSSL类库里，SSL_write函数调用了 SSL_do_handshake ，
		SSL_do_handshake 函数执行时，当前SSL链接握手可能还未完成，且
	*/
	// 2022-12-16 改为 SSL_in_init
	MasterKeyHookFuncBoringSSL = "SSL_in_init"
)

// buffer size times of ebpf perf map
// buffer size = BufferSizeOfEbpfMap * os.pagesize
const BufferSizeOfEbpfMap = 1024

const (
	MasterSecretKeyLogName = "ecapture_masterkey.log"
)
