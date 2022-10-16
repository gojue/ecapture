/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package config

// 最终使用openssl参数
type OpensslConfig struct {
	eConfig
	Curlpath   string `json:"curlPath"` //curl的文件路径
	Openssl    string `json:"openssl"`
	Pthread    string `json:"pThread"`    // /lib/x86_64-linux-gnu/libpthread.so.0
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
