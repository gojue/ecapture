/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

type IConfig interface {
	Check() error //检测配置合法性
	GetPid() uint64
	GetHex() bool
	GetDebug() bool
}

type eConfig struct {
	Pid   uint64
	IsHex bool
	Debug bool
}

func (e *eConfig) GetPid() uint64 {
	return e.Pid
}

func (e *eConfig) GetDebug() bool {
	return e.Debug
}

func (e *eConfig) GetHex() bool {
	return e.IsHex
}
