package proc

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const ElfBuildByCgo = "go_elf"

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
	e := os.Chdir("go_elf")
	if e != nil {
		t.Fatalf("chdir error:%s\n", e.Error())
	}

	p, e := os.Getwd()
	if e != nil {
		t.Fatalf("Getwd error:%s", e.Error())
	}
	t.Logf("pwd:%s", p)

	// go build go_elf
	pathEnv := os.Getenv("PATH")
	t.Logf("env $PATH:%s", pathEnv)

	// mkdir directories
	goBuildPath := filepath.Join(os.TempDir(), "go-build")
	goEnvPath := filepath.Join(os.TempDir(), "go-env")
	e = os.MkdirAll(goBuildPath, os.ModePerm)
	if e != nil {
		t.Fatal(e)
	}
	e = os.MkdirAll(goEnvPath, os.ModePerm)
	if e != nil {
		t.Fatal(e)
	}

	c := exec.Command("go", "build", "-v", ".")

	var outb, errb bytes.Buffer
	c.Stdout = &outb
	c.Stderr = &errb
	e = c.Run()
	t.Logf("output:%s, errput:%s", outb.String(), errb.String())
	if e != nil {
		c.Stderr = os.Stderr
		t.Fatalf("go build failed:%s", e.Error())
	}

	p1 := filepath.Join(p, ElfBuildByCgo)
	ver, err := ExtraceGoVersion(p1)
	t.Logf("Extrace GoVersion from CGO ELF :%s", p1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("version found :%v", ver)
}

func TestGoVersionAfter(t *testing.T) {
	tests := []struct {
		v     GoVersion
		major int
		minor int
		want  bool
	}{
		{GoVersion{1, 15}, 1, 14, true},
		{GoVersion{1, 15}, 1, 15, false},
		{GoVersion{1, 15}, 1, 16, false},
		{GoVersion{2, 0}, 1, 20, true},
		{GoVersion{1, 20}, 2, 0, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d.%d After %d.%d", tt.v.major, tt.v.minor, tt.major, tt.minor), func(t *testing.T) {
			if got := tt.v.After(tt.major, tt.minor); got != tt.want {
				t.Errorf("GoVersion.After() = %v, want %v", got, tt.want)
			}
		})
	}
}
