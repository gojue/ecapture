package handlers

import (
	"fmt"
	"strings"
)

const (
	// ModeText Capture mode types for handlers
	ModeText         = "text"
	ModePcap         = "pcap"
	ModePcapng       = "pcapng"
	ModeKeylog       = "keylog"
	ModeKey          = "key"
	TextSourceHook   = "hook"
	TextSourcePcapng = "pcapng"
)

// NormalizeTextSource validates how TLS text is captured. Other output modes
// do not accept the pcapng text source.
func NormalizeTextSource(mode, source string) (string, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = TextSourceHook
	}
	if source != TextSourceHook && source != TextSourcePcapng {
		return "", fmt.Errorf("unsupported text source %q (supported: hook, pcapng)", source)
	}
	if source == TextSourcePcapng && mode != "" && mode != ModeText {
		return "", fmt.Errorf("text source pcapng requires text capture mode")
	}
	return source, nil
}

func IsPcapngText(mode, source string) bool {
	return mode == ModeText && source == TextSourcePcapng
}

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
