package main

import (
	"ecapture/cli"
	"github.com/cilium/ebpf/rlimit"
	"log"
)

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	cli.Start()
	return
}
