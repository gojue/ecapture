package user

const (
	PROBE_TYPE_UPROBE = "uprobe"
	PROBE_TYPE_KPROBE = "kprobe"
	PROBE_TYPE_TP     = "tracepoint"
	PROBE_TYPE_XDP    = "XDP"
)

const (
	MODULE_NAME_BASH     = "EBPFProbeBash"
	MODULE_NAME_MYSQLD57 = "EBPFProbeMysqld57"
	MODULE_NAME_OPENSSL  = "EBPFProbeOPENSSL"
)

const (
	ELF_TYPE_BIN uint8 = 1
	ELF_TYPE_SO  uint8 = 2
)
