//go:build windows
// +build windows

package kernel

import (
	"golang.org/x/sys/windows"
)

// hostVersionWindows returns the Windows build number as a Version.
func hostVersionWindows() (Version, error) {
	ver := windows.RtlGetVersion()
	if ver == nil {
		return 0, ErrNonLinux
	}
	// Use the Windows build number directly as the version code.
	// Windows 10 build 17763, Windows 11 starts at 22000.
	hostVersion = Version(ver.BuildNumber)
	return hostVersion, nil
}
