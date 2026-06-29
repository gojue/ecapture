//go:build !linux && !windows
// +build !linux,!windows

package kernel

// hostVersionWindows is a stub on non-Windows.
func hostVersionWindows() (Version, error) {
	return 0, ErrNonLinux
}
