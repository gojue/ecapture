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

package config

// 最终使用openssl参数
type OpensslConfig struct {
	eConfig
	Curlpath string `json:"curlPath"` //curl的文件路径
	Openssl  string `json:"openssl"`
	//Pthread    string `json:"pThread"`    // /lib/x86_64-linux-gnu/libpthread.so.0
	Write      string `json:"write"`      // Write  the  raw  packets  to file rather than parsing and printing them out.
	Ifname     string `json:"ifName"`     // (TC Classifier) Interface name on which the probe will be attached.
	Port       uint16 `json:"port"`       // capture port
	SslVersion string `json:"sslVersion"` // openssl version like 1.1.1a/1.1.1f/boringssl_1.1.1
	ElfType    uint8  //
	IsAndroid  bool   //	is Android OS ?
}

func NewOpensslConfig() *OpensslConfig {
	config := &OpensslConfig{}
	return config
}
