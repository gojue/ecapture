/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

// 最终使用openssl参数
type OpensslConfig struct {
	eConfig
	Curlpath string `json:"curlpath"` //curl的文件路径
	Openssl  string `json:"openssl"`
	Pthread  string `json:"pthread"` // /lib/x86_64-linux-gnu/libpthread.so.0
	Write    string `json:"write"`   // Write  the  raw  packets  to file rather than parsing and printing them out.
	Ifname   string `json:"ifname"`  // (TC Classifier) Interface name on which the probe will be attached.
	Port     uint16 `json:"port"`    // capture port
	elfType  uint8  //
}

func NewOpensslConfig() *OpensslConfig {
	config := &OpensslConfig{}
	return config
}
