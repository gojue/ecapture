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
	"fmt"
	"net/url"
	"strings"
	"time"
)

// WriterFactory creates OutputWriter instances based on address and configuration.
type WriterFactory struct{}

// NewWriterFactory creates a new writer factory.
func NewWriterFactory() *WriterFactory {
	return &WriterFactory{}
}

// CreateWriter creates an OutputWriter based on the address format:
// - Empty or "stdout": stdout
// - "tcp://host:port": TCP connection
// - "ws://host:port/path" or "wss://host:port/path": WebSocket connection
// - Any other path: local file
func (f *WriterFactory) CreateWriter(addr string, rotateConfig *RotateConfig) (OutputWriter, error) {
	if addr == "" || addr == "stdout" {
		return NewStdoutWriter(), nil
	}

	// Check for TCP protocol
	if strings.HasPrefix(addr, "tcp://") {
		address := strings.TrimPrefix(addr, "tcp://")
		return NewTcpWriter(address, 4096) // 4KB buffer
	}

	// Check for WebSocket protocol
	if strings.HasPrefix(addr, "ws://") || strings.HasPrefix(addr, "wss://") {
		parsedURL, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid WebSocket URL %s: %w", addr, err)
		}

		if parsedURL.Scheme != "ws" && parsedURL.Scheme != "wss" {
			return nil, fmt.Errorf("WebSocket URL must use ws:// or wss:// scheme")
		}

		return NewWebSocketWriter(addr)
	}

	// Default to file
	config := FileWriterConfig{
		Path:       addr,
		BufferSize: 0, // 0KB buffer for files
	}

	// Apply rotation config if provided
	if rotateConfig != nil {
		config.EnableRotate = rotateConfig.EnableRotate
		config.MaxSizeMB = rotateConfig.MaxSizeMB
		config.MaxInterval = rotateConfig.MaxInterval
	}

	return NewFileWriter(config)
}

// RotateConfig configures file rotation settings.
type RotateConfig struct {
	EnableRotate bool
	MaxSizeMB    int           // Maximum file size in MB
	MaxInterval  time.Duration // Maximum time interval
}
