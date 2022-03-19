package main

import (
	"ecapture/cli"
	"github.com/cilium/ebpf/rlimit"
	"log"
)

func main() {

	// 环境检测 @TODO
	// 系统内核版本检测
	// BTF支持情况检测

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	cli.Start()
	return
}
