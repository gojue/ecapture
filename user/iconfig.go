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

func (this *eConfig) GetPid() uint64 {
	return this.Pid
}

func (this *eConfig) GetDebug() bool {
	return this.Debug
}

func (this *eConfig) GetHex() bool {
	return this.IsHex
}

func (this *eConfig) SetPid(pid uint64) {
	this.Pid = pid
}

func (this *eConfig) SetDebug(b bool) {
	this.Debug = b
}

func (this *eConfig) SetHex(isHex bool) {
	this.IsHex = isHex
}
