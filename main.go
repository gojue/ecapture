package main

import (
	"github.com/gojue/ecapture/cli"
	"github.com/gojue/ecapture/pkg/util/kernel"
	_ "github.com/shuLhan/go-bindata" // add for bindata in Makefile
	"log"
	"runtime"
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

	cli.Start()
}
