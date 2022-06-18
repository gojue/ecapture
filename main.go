package main

import (
	"ecapture/cli"
	"ecapture/pkg/util/ebpf"
	"ecapture/pkg/util/kernel"
	"fmt"
	"log"
)

const (
	BTF_NOT_SUPPORT = "You can compile a no BTF version by youeself with command `make nocore`,Please read Makefile for more info."
)

var (
	enableCORE = "true"
)

func main() {

	// 环境检测
	// 系统内核版本检测
	kv, err := kernel.HostVersion()
	if err != nil {
		log.Fatal(err)
	}
	if kv < kernel.VersionCode(4, 18, 0) {
		log.Fatalf("Linux Kernel version %v is not supported. Need > 4.18 .", kv)
	}

	// changed by go build '-ldflags X'
	if enableCORE == "true" {
		// BTF支持情况检测
		enable, e := ebpf.IsEnableBTF()
		if e != nil {
			log.Fatal(fmt.Sprintf("Can't found BTF config with error:%v.\n"+BTF_NOT_SUPPORT, e))
		}
		if !enable {
			log.Fatal("BTF not support, please check it. shell: cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF \n " +
				BTF_NOT_SUPPORT)
		}
	}

	// TODO check UPROBE

	cli.Start()
	return
}
