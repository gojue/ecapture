/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

type IConfig interface {
	Check() error //检测配置合法性
	GetPid() uint64
	GetHex() bool
	GetDebug() bool
	SetPid(uint64)
	SetHex(bool)
	SetDebug(bool)
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

func (e *eConfig) SetPid(pid uint64) {
	e.Pid = pid
}

func (e *eConfig) SetDebug(b bool) {
	e.Debug = b
}

func (e *eConfig) SetHex(isHex bool) {
	e.IsHex = isHex
}
