package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const ELF_BUILD_BY_CGO = "go_elf/go_elf"

func TestExtraceGoVersion(t *testing.T) {
	path := fmt.Sprintf("/proc/%d/exe", os.Getppid())
	ver, err := ExtraceGoVersion(path)
	if err != nil {
		t.Log(err)
		return
	}
	t.Log(ver)
}

// cd go_elf
// CGO_ENABLED=1 go build .
func TestExtraceGoVersionGccgo(t *testing.T) {
	p, e := os.Getwd()
	if e != nil {
		t.Fatalf("Getwd error:%v", e)
	}
	t.Logf("pwd:%s", p)

	p1 := filepath.Join(p, ELF_BUILD_BY_CGO)
	ver, err := ExtraceGoVersion(p1)
	if err != nil {
		t.Log(err)
		return
	}
	t.Logf("Extrace GoVersion %v from CGO ELF :%s", ver, ELF_BUILD_BY_CGO)
}
