package main

import (
	"ecapture/cli"
	"ecapture/pkg/util/ebpf"
	"ecapture/pkg/util/kernel"
	"log"

	_ "github.com/shuLhan/go-bindata" // add for bindata in Makefile
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
	if kv < kernel.VersionCode(4, 15, 0) {
		log.Fatalf("Linux Kernel version %v is not supported. Need > 4.15 .", kv)
	}

	// 检测是否是容器
	isContainer, err := ebpf.IsContainer()
	if err != nil {
		log.Fatal("Check container error:", err)
	}

	if isContainer {
		log.Printf("Your environment is a container. We will not detect the BTF config.")
	} else {
		enable, e := ebpf.IsEnableBPF()
		if e != nil {
			log.Fatalf("Kernel config read failed, error:%v", e)
		}

		if !enable {
			log.Fatalf("Kernel not support, error:%v", e)
		}

		// changed by go build '-ldflags X'
		if enableCORE == "true" {
			// BTF支持情况检测
			enable, e := ebpf.IsEnableBTF()
			if e != nil {
				log.Fatalf("Can't found BTF config with error:%v.\n"+BTF_NOT_SUPPORT, e)
			}
			if !enable {
				log.Fatal("BTF not support, please check it. shell: cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF \n " +
					BTF_NOT_SUPPORT)
			}
		}
	}

	cli.Start()
}
