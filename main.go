package main

import (
	_ "github.com/shuLhan/go-bindata" // add for bindata in Makefile

	"github.com/gojue/ecapture/cli"
)

func main() {
	cli.Start()
}
