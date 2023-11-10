package main

import (
	"ecapture/cli"
	"ecapture/pkg/util/ebpf"
	"ecapture/pkg/util/kernel"
	_ "github.com/shuLhan/go-bindata" // add for bindata in Makefile
	"log"
	"runtime"
)

const (
	BtfNotSupport = "You can compile the BTF-free version by using the command `make nocore`, please read the Makefile for more information."
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
	switch runtime.GOARCH {
	case "amd64":
		if kv < kernel.VersionCode(4, 18, 0) {
			log.Fatalf("The Linux/Android Kernel version %v (x86_64) is not supported. Requires a version greater than 4.18.", kv)
		}
	case "arm64":
		if kv < kernel.VersionCode(5, 5, 0) {
			log.Fatalf("The Linux/Android Kernel version %v (aarch64) is not supported. Requires a version greater than 5.5.", kv)
		}
	default:
		log.Fatalf("Unsupported CPU arch:%v. ", runtime.GOARCH)
	}

	// 检测是否是容器
	isContainer, err := ebpf.IsContainer()
	if err != nil {
		log.Fatal("Check container error:", err)
	}

	if isContainer {
		log.Printf("Your environment is like a container. We won't be able to detect the BTF configuration.")
	} else {
		enable, e := ebpf.IsEnableBPF()
		if e != nil {
			log.Fatalf("Failed to read kernel configuration., error:%v", e)
		}

		if !enable {
			log.Fatalf("Unsupported kernel, error:%v", e)
		}

		// changed by go build '-ldflags X'
		if enableCORE == "true" {
			// BTF支持情况检测
			enable, e := ebpf.IsEnableBTF()
			if e != nil {
				log.Fatalf("Unable to find BTF configuration due to an error:%v.\n"+BtfNotSupport, e)
			}
			if !enable {
				log.Fatal("BTF is not supported, please check it. shell: cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF \n " +
					BtfNotSupport)
			}
		}
	}

	cli.Start()
}
