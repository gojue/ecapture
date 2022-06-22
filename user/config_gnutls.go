/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

// 最终使用openssl参数
type GnutlsConfig struct {
	eConfig
	Curlpath string `json:"curlpath"` //curl的文件路径
	Gnutls   string `json:"gnutls"`
	elfType  uint8  //
}

func NewGnutlsConfig() *GnutlsConfig {
	config := &GnutlsConfig{}
	return config
}
