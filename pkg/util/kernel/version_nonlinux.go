//go:build !linux
// +build !linux

package kernel

import (
	"fmt"
	"runtime"
)

// Version is a numerical representation of a kernel version (or OS build on non-Linux).
type Version uint32

var hostVersion Version

// String returns a string representing the version.
func (v Version) String() string {
	if runtime.GOOS == "windows" {
		// On Windows, show the build number
		return fmt.Sprintf("Windows Build %d", uint32(v))
	}
	a, b, c := v>>16, v>>8&0xff, v&0xff
	return fmt.Sprintf("%d.%d.%d", a, b, c)
}

// HostVersion returns the running kernel version of the host.
// On non-Linux platforms, this returns a platform-specific version number.
func HostVersion() (Version, error) {
	if hostVersion != 0 {
		return hostVersion, nil
	}

	if runtime.GOOS == "windows" {
		// On Windows, use RtlGetVersion to get the build number
		return hostVersionWindows()
	}

	return 0, ErrNonLinux
}

// ParseVersion parses a string in the format of x.x.x to a Version.
func ParseVersion(s string) Version {
	var a, b, c byte
	_, err := fmt.Sscanf(s, "%d.%d.%d", &a, &b, &c)
	if err != nil {
		return Version(0)
	}
	return VersionCode(a, b, c)
}

// VersionCode returns a Version computed from the individual parts of a x.x.x version.
func VersionCode(major, minor, patch byte) Version {
	return Version((uint32(major) << 16) + (uint32(minor) << 8) + uint32(patch))
}
