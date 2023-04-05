package main

import "C"
import "fmt"

//export eprint
func eprint(i C.int) {
	fmt.Printf("eCapture unit testing : i = %d\n", uint32(i))
}
