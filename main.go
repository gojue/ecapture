package main

import (
	"ecapture/cli"
	"ecapture/pkg/util/kernel"
	"log"
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

	// BTF支持情况检测

	cli.Start()
	return
}
