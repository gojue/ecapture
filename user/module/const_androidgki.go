//go:build androidgki
// +build androidgki

package module

// buffer size times of ebpf perf map
// buffer size = BufferSizeOfEbpfMap * os.pagesize
const BufferSizeOfEbpfMap = 1024
