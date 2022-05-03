package user

const (
	PROBE_TYPE_UPROBE = "uprobe"
	PROBE_TYPE_KPROBE = "kprobe"
	PROBE_TYPE_TP     = "tracepoint"
	PROBE_TYPE_XDP    = "XDP"
)

const (
	MODULE_NAME_BASH     = "EBPFProbeBash"
	MODULE_NAME_MYSQLD   = "EBPFProbeMysqld"
	MODULE_NAME_POSTGRES = "EBPFProbePostgres"
	MODULE_NAME_OPENSSL  = "EBPFProbeOPENSSL"
	MODULE_NAME_GNUTLS   = "EBPFProbeGNUTLS"
	MODULE_NAME_NSPR     = "EBPFProbeNSPR"
)

const (
	ELF_TYPE_BIN uint8 = 1
	ELF_TYPE_SO  uint8 = 2
)
const (
	BASH_ERRNO_DEFAULT int = 128
)
const (
	X86_BINARY_PREFIX    = "/lib/x86_64-linux-gnu"
	OTHERS_BINARY_PREFIX = "/usr/lib"
)
