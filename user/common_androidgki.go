//go:build androidgki
// +build androidgki

package user

const (
	LD_LOAD_PATH = "/etc/ld.so.conf"
)

// https://source.android.com/devices/architecture/vndk/linker-namespace
var (
	default_so_paths = []string{
		"/data/asan/system/lib64",
		"/apex/com.android.conscrypt/lib64",
		"/apex/com.android.runtime/lib64/bionic",
	}
)
