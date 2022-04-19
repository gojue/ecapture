package main

import (
	"ecapture/cli"
	"ecapture/pkg/util/ebpf"
	"ecapture/pkg/util/kernel"
	"log"
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
			log.Fatal(err)
		}
		if !enable {
			log.Fatal("BTF not support, please check it. shell: cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF \n " +
				"Or you can compile a no BTF version with youeself by `make nocore` command,Please read Makefile for more info.")
		}
	}

	cli.Start()
	return
}
