/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package user

import "ecapture/pkg/util/kernel"

type IConfig interface {
	Check() error //检测配置合法性
	GetPid() uint64
	GetHex() bool
	GetDebug() bool
	SetPid(uint64)
	SetHex(bool)
	SetDebug(bool)
	EnableGlobalVar() bool //
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

func (this *eConfig) EnableGlobalVar() bool {
	kv, err := kernel.HostVersion()
	if err != nil {
		//log.Fatal(err)
		return true
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		//log.Fatalf("Linux Kernel version %v is not supported. Need > 4.18 .", kv)
		return false
	}
	return true
}
