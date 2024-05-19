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

import "encoding/json"

// GnutlsConfig 最终使用openssl参数
type GnutlsConfig struct {
	BaseConfig
	//Curl path string `json:"curlpath"` //curl的文件路径
	Gnutls  string `json:"gnutls"`
	ElfType uint8  //
}

func NewGnutlsConfig() *GnutlsConfig {
	config := &GnutlsConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (gc *GnutlsConfig) Bytes() []byte {
	b, e := json.Marshal(gc)
	if e != nil {
		return []byte{}
	}
	return b
}
