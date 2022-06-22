/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

// 最终使用openssl参数
type NsprConfig struct {
	eConfig
	Firefoxpath string `json:"firefoxpath"` //curl的文件路径
	Nsprpath    string `json:"nsprpath"`
	elfType     uint8  //
}

func NewNsprConfig() *NsprConfig {
	config := &NsprConfig{}
	return config
}
