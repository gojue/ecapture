package handlers

const (
	// ModeText Capture mode types for handlers
	ModeText   = "text"
	ModePcap   = "pcap"
	ModePcapng = "pcapng"
	ModeKeylog = "keylog"
	ModeKey    = "key"
)

// IsModeText checks if the mode is text
func IsModeText(mode string) bool {
	return mode == ModeText
}

// IsModePcapng checks if the mode is pcap or pcapng
func IsModePcapng(mode string) bool {
	return mode == ModePcap || mode == ModePcapng
}

// IsModeKeylog checks if the mode is keylog or key
func IsModeKeylog(mode string) bool {
	return mode == ModeKeylog || mode == ModeKey
}
