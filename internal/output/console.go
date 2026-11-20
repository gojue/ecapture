// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/gojue/ecapture/v2/internal/domain"
)

// ConsolePublisher serializes complete records and labels every physical line.
// It borrows stdout/stderr and never closes either process descriptor.
type ConsolePublisher struct {
	writer io.Writer
	name   string
	mu     sync.Mutex
}

func NewConsolePublisher(name string, writer io.Writer) *ConsolePublisher {
	return &ConsolePublisher{name: name, writer: writer}
}
func (p *ConsolePublisher) Name() string { return p.name }
func (p *ConsolePublisher) Close() error { return nil }
func (p *ConsolePublisher) PublishLog(ctx context.Context, r domain.OperationalLogRecord) error {
	var record map[string]any
	message := r.Message
	if json.Unmarshal([]byte(r.Message), &record) == nil {
		if v, ok := record["message"].(string); ok {
			message = v
		}
		// Preserve operational fields (errors, startup addresses, etc.) in readable output.
		delete(record, "message")
		if len(record) > 0 {
			fields, _ := json.Marshal(record)
			message = string(fields) + " " + message
		}
	}
	return p.write(ctx, fmt.Sprintf("[log_type=log module=%s] ", r.Module), []byte(message))
}
func (p *ConsolePublisher) PublishEvent(ctx context.Context, e domain.CapturedEventEnvelope) error {
	payload := e.Payload
	if e.Format == domain.CaptureFormatPcapng {
		payload = []byte(fmt.Sprintf("encoded_bytes=%d", len(e.Payload)))
	}
	if e.Format != domain.CaptureFormatText && e.Format != domain.CaptureFormatKeylog && e.Format != domain.CaptureFormatPcapng {
		return fmt.Errorf("unsupported console format %q", e.Format)
	}
	return p.write(ctx, fmt.Sprintf("[log_type=event capture_format=%s module=%s] ", e.Format, e.Module), payload)
}
func (p *ConsolePublisher) write(ctx context.Context, prefix string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Escape terminal control characters other than line/tab separators.
	var safe strings.Builder
	for _, r := range string(bytes.TrimSuffix(data, []byte("\n"))) {
		if r < ' ' && r != '\n' && r != '\t' || r == 0x7f {
			fmt.Fprintf(&safe, "\\x%02x", r)
		} else {
			safe.WriteRune(r)
		}
	}
	var record strings.Builder
	for _, line := range strings.Split(safe.String(), "\n") {
		record.WriteString(prefix)
		record.WriteString(line)
		record.WriteByte('\n')
	}
	n, err := io.WriteString(p.writer, record.String())
	if err == nil && n != record.Len() {
		err = io.ErrShortWrite
	}
	return err
}
