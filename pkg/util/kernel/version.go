//go:build linux
// +build linux

package kernel

import (
	"fmt"
)

// Version is a numerical representation of a kernel version
type Version uint32

var hostVersion Version

// String returns a string representing the version in x.x.x format
func (v Version) String() string {
	a, b, c := v>>16, v>>8&0xff, v&0xff
	return fmt.Sprintf("%d.%d.%d", a, b, c)
}

// HostVersion returns the running kernel version of the host
func HostVersion() (Version, error) {
	if hostVersion != 0 {
		return hostVersion, nil
	}
	kv, err := CurrentKernelVersion()
	if err != nil {
		return 0, err
	}
	hostVersion = Version(kv)
	return hostVersion, nil
}

// ParseVersion parses a string in the format of x.x.x to a Version
func ParseVersion(s string) Version {
	var a, b, c byte
	_, err := fmt.Sscanf(s, "%d.%d.%d", &a, &b, &c)
	if err != nil {
		return Version(0)
	}
	return VersionCode(a, b, c)
}

// VersionCode returns a Version computed from the individual parts of a x.x.x version
func VersionCode(major, minor, patch byte) Version {
	// KERNEL_VERSION(a,b,c) = (a << 16) + (b << 8) + (c)
	// Per https://github.com/torvalds/linux/blob/db7c953555388571a96ed8783ff6c5745ba18ab9/Makefile#L1250
	return Version((uint32(major) << 16) + (uint32(minor) << 8) + uint32(patch))
}
