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
	PROBE_TYPE_UPROBE = "uprobe"
	PROBE_TYPE_KPROBE = "kprobe"
	PROBE_TYPE_TP     = "tracepoint"
	PROBE_TYPE_XDP    = "XDP"
)

const (
	MODULE_NAME_BASH     = "EBPFProbeBash"
	MODULE_NAME_MYSQLD   = "EBPFProbeMysqld"
	MODULE_NAME_POSTGRES = "EBPFProbePostgres"
	MODULE_NAME_OPENSSL  = "EBPFProbeOPENSSL"
	MODULE_NAME_GNUTLS   = "EBPFProbeGNUTLS"
	MODULE_NAME_NSPR     = "EBPFProbeNSPR"
	MODULE_NAME_GOSSL    = "EBPFProbeGoSSL"
)

const (
	BASH_ERRNO_DEFAULT int = 128
)

const (
	MasterKeyHookFuncOpenSSL   = "SSL_write"
	MasterKeyHookFuncBoringSSL = "SSL_do_handshake"
)
