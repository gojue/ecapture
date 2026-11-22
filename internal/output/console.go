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

// ConsolePublisher serializes complete records. Text events have one prefix and
// retain their payload bytes; operational logs and keylogs label every line.
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
	return p.writeLines(ctx, fmt.Sprintf("[log_type=log module=%s] ", r.Module), []byte(message))
}
func (p *ConsolePublisher) PublishEvent(ctx context.Context, e domain.CapturedEventEnvelope) error {
	switch e.Format {
	case domain.CaptureFormatPcapng:
		return ctx.Err()
	case domain.CaptureFormatText:
		record := append([]byte(fmt.Sprintf("[log_type=event capture_format=%s module=%s] ", e.Format, e.Module)), e.Payload...)
		// Keep the next record on its own line without altering the payload.
		if len(e.Payload) == 0 || e.Payload[len(e.Payload)-1] != '\n' {
			record = append(record, '\n')
		}
		return p.write(ctx, record)
	case domain.CaptureFormatKeylog:
		return p.writeLines(ctx, fmt.Sprintf("[log_type=event capture_format=%s module=%s] ", e.Format, e.Module), e.Payload)
	default:
		return fmt.Errorf("unsupported console format %q", e.Format)
	}
}
func (p *ConsolePublisher) writeLines(ctx context.Context, prefix string, data []byte) error {
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
	return p.write(ctx, []byte(record.String()))
}

func (p *ConsolePublisher) write(ctx context.Context, record []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n, err := p.writer.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	return err
}
