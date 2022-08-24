package module

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
	MODULE_NAME_GOSSL    = "EBPFProbeGoSSL"
)
const (
	BASH_ERRNO_DEFAULT int = 128
)
