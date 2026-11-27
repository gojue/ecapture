// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package writers

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type EventFormat string

const (
	EventFormatText   EventFormat = "text"
	EventFormatKeylog EventFormat = "keylog"
	EventFormatPcapng EventFormat = "pcapng"
)

// EventSinkOptions keeps representation policy separate from URI parsing.
type EventSinkOptions struct {
	Address      string
	Format       EventFormat
	RotateConfig *RotateConfig
	Sensitive    bool // restrict file permissions for reconstructed plaintext
	Append       bool // preserve native artifacts across probe generations
}

type sinkAddress struct {
	kind string
	name string
}

// NormalizeEventAddress applies the legacy TLS file flags as mode-specific
// aliases for the primary event destination. Repeating the call is safe.
func NormalizeEventAddress(format EventFormat, address, keylogFile, pcapFile string) (string, error) {
	legacy := ""
	switch format {
	case EventFormatText:
		// Empty remains the compatible stdout default.
	case EventFormatKeylog:
		legacy = keylogFile
	case EventFormatPcapng:
		legacy = pcapFile
	default:
		return "", fmt.Errorf("unsupported event format %q", format)
	}
	if address == "" {
		address = legacy
	} else if legacy != "" && address != legacy {
		return "", fmt.Errorf("event destination %q conflicts with legacy %s file %q", address, format, legacy)
	}
	return address, nil
}

// ValidateChannelSeparation prevents operational text from corrupting an
// unframed binary pcapng stream.
func ValidateChannelSeparation(format EventFormat, eventAddress, loggerAddress string) error {
	if format == EventFormatPcapng && eventAddress == "stdout" && loggerAddress == "stdout" {
		return fmt.Errorf("operational logs and binary pcapng cannot both use stdout")
	}
	return nil
}

// WriterFactory is the single constructor for raw byte destinations.
type WriterFactory struct{}

func NewWriterFactory() *WriterFactory { return &WriterFactory{} }

// ValidateArtifactFile accepts regular local files and pre-created FIFOs.
// Terminal devices and network destinations are not native artifact paths.
func ValidateArtifactFile(address string) error {
	if address == "" {
		return fmt.Errorf("native capture output requires an explicit file path")
	}
	if address == "stdout" || address == "stderr" || address == "-" {
		return fmt.Errorf("native capture artifact cannot use a terminal destination")
	}
	parsed, err := parseSinkAddress(address)
	if err != nil {
		return err
	}
	if parsed.kind != "file" {
		return fmt.Errorf("native capture artifact %q must be a local file", address)
	}
	info, err := os.Stat(parsed.name)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect native capture artifact: %w", err)
	}
	if err == nil && !info.Mode().IsRegular() && info.Mode()&os.ModeNamedPipe == 0 {
		return fmt.Errorf("native capture artifact %q must be a regular file or FIFO", address)
	}
	if err == nil {
		for _, terminal := range []*os.File{os.Stdout, os.Stderr} {
			if terminalInfo, statErr := terminal.Stat(); statErr == nil && os.SameFile(info, terminalInfo) {
				return fmt.Errorf("native capture artifact cannot share stdout or stderr")
			}
		}
	}
	return nil
}

// ValidateCaptureArtifacts keeps native keylog/pcapng files separate from the
// process-wide display endpoints. Text capture may request either artifact;
// native modes require their corresponding file explicitly.
func ValidateCaptureArtifacts(mode, keylogFile, pcapFile string) error {
	for _, artifact := range []struct{ flag, address string }{
		{"--keylogfile", keylogFile}, {"--pcapfile", pcapFile},
	} {
		if artifact.address != "" {
			if err := ValidateArtifactFile(artifact.address); err != nil {
				return fmt.Errorf("%s: %w", artifact.flag, err)
			}
		}
	}
	switch mode {
	case "key", "keylog":
		if keylogFile == "" {
			return fmt.Errorf("keylog mode requires --keylogfile")
		}
	case "pcap", "pcapng":
		if pcapFile == "" {
			return fmt.Errorf("pcapng mode requires --pcapfile")
		}
	}
	return nil
}

// byteSinkPolicy contains transport construction details that vary by semantic
// channel. Public callers still choose between operational and event sinks;
// this policy only removes duplication in the shared ByteSink construction.
type byteSinkPolicy struct {
	fileConfig    FileWriterConfig
	tcpBufferSize int
}

// ValidateEventSinkAddress rejects malformed or incompatible configurations
// without opening a file or network connection.
func (f *WriterFactory) ValidateEventSinkAddress(options EventSinkOptions) error {
	if options.Format != EventFormatText && options.Format != EventFormatKeylog && options.Format != EventFormatPcapng {
		return fmt.Errorf("unsupported event format %q", options.Format)
	}
	if options.Address == "" {
		if options.Format == EventFormatText {
			if options.RotateConfig != nil && options.RotateConfig.EnableRotate {
				return fmt.Errorf("event rotation requires a file destination")
			}
			return nil
		}
		return fmt.Errorf("%s output requires an explicit destination", options.Format)
	}
	if options.Format == EventFormatPcapng && options.RotateConfig != nil && options.RotateConfig.EnableRotate {
		return fmt.Errorf("pcapng output does not support byte-stream rotation")
	}
	parsed, err := parseSinkAddress(options.Address)
	if err != nil {
		return err
	}
	if options.RotateConfig != nil && options.RotateConfig.EnableRotate && parsed.kind != "file" {
		return fmt.Errorf("event rotation requires a file destination")
	}
	return nil
}

// CreateEventSink constructs the primary captured-event ByteSink. Empty means
// stdout only for text; keylog and pcapng require an explicit address.
func (f *WriterFactory) CreateEventSink(options EventSinkOptions) (ByteSink, error) {
	if err := f.ValidateEventSinkAddress(options); err != nil {
		return nil, err
	}
	address := options.Address
	if address == "" {
		address = "stdout"
	}

	fileConfig := FileWriterConfig{
		Truncate: !options.Append && (options.Format == EventFormatKeylog || options.Format == EventFormatPcapng),
	}
	if options.Format == EventFormatPcapng {
		fileConfig.BufferSize = 64 * 1024
	}
	if options.Format == EventFormatKeylog || options.Format == EventFormatPcapng {
		fileConfig.Permissions = 0600
	}
	if options.Sensitive {
		fileConfig.Permissions = 0600
	}
	applyRotateConfig(&fileConfig, options.RotateConfig)

	return f.createByteSink(address, byteSinkPolicy{
		fileConfig:    fileConfig,
		tcpBufferSize: 4096,
	})
}

// CreateOperationalSink constructs a non-console operational destination. The
// caller independently adds stderr and owns the returned sink.
func (f *WriterFactory) CreateOperationalSink(address string, rotateConfig *RotateConfig) (ByteSink, error) {
	if address == "" {
		return nil, fmt.Errorf("operational sink address cannot be empty")
	}
	fileConfig := FileWriterConfig{Truncate: true}
	applyRotateConfig(&fileConfig, rotateConfig)
	return f.createByteSink(address, byteSinkPolicy{fileConfig: fileConfig})
}

// CreateJSONSink opens a typed-record destination. Files append with sensitive
// permissions; remote connection establishment has one bounded deadline.
func (f *WriterFactory) CreateJSONSink(address string) (ByteSink, error) {
	parsed, err := parseSinkAddress(address)
	if err != nil {
		return nil, err
	}
	if parsed.kind == "file" {
		if err := ValidateArtifactFile(address); err != nil {
			return nil, err
		}
		return NewFileWriter(FileWriterConfig{Path: parsed.name, Permissions: 0600})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch parsed.kind {
	case "tcp":
		return newTCPWriterWithContext(ctx, parsed.name, 4096)
	case "ws", "wss":
		return newWebSocketWriterWithContext(ctx, address)
	default:
		return nil, fmt.Errorf("JSON output requires a file or remote destination")
	}
}

func (f *WriterFactory) createByteSink(address string, policy byteSinkPolicy) (ByteSink, error) {
	parsed, err := parseSinkAddress(address)
	if err != nil {
		return nil, err
	}
	switch parsed.kind {
	case "stdout":
		return NewStdoutWriter(), nil
	case "file":
		config := policy.fileConfig
		config.Path = parsed.name
		return NewFileWriter(config)
	case "tcp":
		return NewTcpWriter(parsed.name, policy.tcpBufferSize)
	case "ws", "wss":
		return NewWebSocketWriter(address)
	default:
		return nil, fmt.Errorf("unsupported sink kind %q", parsed.kind)
	}
}

func applyRotateConfig(config *FileWriterConfig, rotateConfig *RotateConfig) {
	if rotateConfig == nil {
		return
	}
	config.EnableRotate = rotateConfig.EnableRotate
	config.MaxSizeMB = rotateConfig.MaxSizeMB
	config.MaxInterval = rotateConfig.MaxInterval
}

// CreateWriter preserves the old text-writer API during migration.
func (f *WriterFactory) CreateWriter(addr string, rotateConfig *RotateConfig) (OutputWriter, error) {
	return f.CreateEventSink(EventSinkOptions{Address: addr, Format: EventFormatText, RotateConfig: rotateConfig})
}

func parseSinkAddress(address string) (sinkAddress, error) {
	if address == "stdout" {
		return sinkAddress{kind: "stdout", name: "stdout"}, nil
	}
	if strings.TrimSpace(address) == "" {
		return sinkAddress{}, fmt.Errorf("sink address cannot be empty")
	}

	parsed, err := url.Parse(address)
	if err != nil {
		return sinkAddress{}, fmt.Errorf("invalid sink address %q: %w", address, err)
	}
	if parsed.Scheme == "" {
		if strings.Contains(address, "://") {
			return sinkAddress{}, fmt.Errorf("malformed sink URI %q", address)
		}
		clean := filepath.Clean(address)
		if clean == "." {
			return sinkAddress{}, fmt.Errorf("file sink path cannot be empty")
		}
		return sinkAddress{kind: "file", name: clean}, nil
	}

	switch strings.ToLower(parsed.Scheme) {
	case "file":
		if parsed.Host != "" && parsed.Host != "localhost" {
			return sinkAddress{}, fmt.Errorf("file URI host must be empty or localhost")
		}
		// url.Parse already unescapes Path. Decoding again changes literal
		// percent-encoded filenames and disagrees with artifact alias checks.
		path := parsed.Path
		if path == "" {
			return sinkAddress{}, fmt.Errorf("file URI path cannot be empty")
		}
		return sinkAddress{kind: "file", name: filepath.Clean(path)}, nil
	case "tcp":
		if parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return sinkAddress{}, fmt.Errorf("invalid TCP sink URI %q", address)
		}
		if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
			return sinkAddress{}, fmt.Errorf("invalid TCP sink address %q: %w", parsed.Host, err)
		}
		return sinkAddress{kind: "tcp", name: parsed.Host}, nil
	case "ws", "wss":
		if parsed.Host == "" {
			return sinkAddress{}, fmt.Errorf("WebSocket sink URI requires a host")
		}
		return sinkAddress{kind: strings.ToLower(parsed.Scheme), name: address}, nil
	default:
		return sinkAddress{}, fmt.Errorf("unsupported sink URI scheme %q", parsed.Scheme)
	}
}

type RotateConfig struct {
	EnableRotate bool
	MaxSizeMB    int
	MaxInterval  time.Duration
}

// NewRotateConfig converts CLI-compatible limits into sink configuration.
// A nil result means rotation is disabled.
func NewRotateConfig(maxSizeMB, maxSeconds uint16) *RotateConfig {
	if maxSizeMB == 0 && maxSeconds == 0 {
		return nil
	}
	return &RotateConfig{
		EnableRotate: true,
		MaxSizeMB:    int(maxSizeMB),
		MaxInterval:  time.Duration(maxSeconds) * time.Second,
	}
}
