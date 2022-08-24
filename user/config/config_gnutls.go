/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package config

// 最终使用openssl参数
type GnutlsConfig struct {
	eConfig
	Curlpath string `json:"curlpath"` //curl的文件路径
	Gnutls   string `json:"gnutls"`
	ElfType  uint8  //
}

func NewGnutlsConfig() *GnutlsConfig {
	config := &GnutlsConfig{}
	return config
}
