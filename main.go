package main

import (
	_ "github.com/shuLhan/go-bindata" // add for bindata in Makefile

	"github.com/gojue/ecapture/v2/cli"
)

func main() {
	cli.Start()
}
