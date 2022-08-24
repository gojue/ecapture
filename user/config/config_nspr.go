/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package config

// 最终使用openssl参数
type NsprConfig struct {
	eConfig
	Firefoxpath string `json:"firefoxpath"` //curl的文件路径
	Nsprpath    string `json:"nsprpath"`
	ElfType     uint8  //
}

func NewNsprConfig() *NsprConfig {
	config := &NsprConfig{}
	return config
}
