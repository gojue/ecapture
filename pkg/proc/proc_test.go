package proc

import (
	"fmt"
	"log"
	"os"
	"testing"
)

func TestExtraceGoVersion(t *testing.T) {
	path := fmt.Sprintf("/proc/%d/exe", os.Getppid())
	ver, err := ExtraceGoVersion(path)
	if err != nil {
		t.Log(err)
		return
	}
	log.Println(ver)
}
