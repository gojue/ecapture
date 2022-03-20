//go:build !linux
// +build !linux

package kernel

import (
	"fmt"

	"runtime"
)

var ErrNonLinux = fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)

func KernelVersionFromReleaseString(releaseString string) (uint32, error) {
	return 0, ErrNonLinux
}

func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNonLinux
}
