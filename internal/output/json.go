// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
)

// JSONPublisher owns a ByteSink and writes one typed LogEntry per JSON line.
// It shares the message schema with the binary Protobuf subscription service.
// The CLI owns this publisher; handlers and logging adapters only borrow it.
type JSONPublisher struct {
	sink         writers.ByteSink
	name         string
	mu           sync.Mutex
	closed       bool
	failure      error
	closeErr     error
	writeTimeout time.Duration
}

func NewJSONPublisher(sink writers.ByteSink) (*JSONPublisher, error) {
	if sink == nil || isNilValue(sink) {
		return nil, fmt.Errorf("JSON output sink cannot be nil")
	}
	return &JSONPublisher{sink: sink, name: "json:" + sink.Name(), writeTimeout: 5 * time.Second}, nil
}

func (p *JSONPublisher) Name() string { return p.name }

func (p *JSONPublisher) PublishLog(ctx context.Context, record domain.OperationalLogRecord) error {
	return p.publish(ctx, LogEntryForRecord(record))
}

func (p *JSONPublisher) PublishEvent(ctx context.Context, event domain.CapturedEventEnvelope) error {
	return p.publish(ctx, LogEntryForEvent(event))
}

func (p *JSONPublisher) publish(ctx context.Context, entry *pb.LogEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return fmt.Errorf("%s: %w", p.name, io.ErrClosedPipe)
	}
	if p.failure != nil {
		return p.failure
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := protocol.ValidateLogEntry(entry); err != nil {
		return err
	}
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode %s record: %w", p.name, err)
	}
	data = append(data, '\n')
	err = p.withWriteTimeout(func() error {
		n, err := p.sink.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("write %s record: %w", p.name, err)
		}
		if err := p.sink.Flush(); err != nil {
			return fmt.Errorf("flush %s record: %w", p.name, err)
		}
		return nil
	})
	if err != nil {
		p.failure = err
		return p.failure
	}
	return nil
}

// withWriteTimeout bounds interruptible network I/O without a goroutine for
// each successful write. The caller holds mu until any fired callback joins:
// a late Abort must never reach a subsequent record or lifecycle operation.
// Regular files do not implement Abort and retain their ordinary I/O behavior.
func (p *JSONPublisher) withWriteTimeout(write func() error) error {
	aborter, ok := p.sink.(interface{ Abort() })
	if !ok {
		return write()
	}
	done := make(chan struct{})
	timer := time.AfterFunc(p.writeTimeout, func() {
		defer close(done)
		aborter.Abort()
	})
	err := write()
	if timer.Stop() {
		return err
	}
	<-done
	return errors.Join(err, fmt.Errorf("%s output timed out after %s: %w", p.name, p.writeTimeout, context.DeadlineExceeded))
}

// Close flushes and closes the owned sink once, preserving earlier stream errors.
func (p *JSONPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	err := p.withWriteTimeout(func() error {
		var flushErr, closeErr error
		if err := p.sink.Flush(); err != nil {
			flushErr = fmt.Errorf("flush %s: %w", p.name, err)
		}
		if err := p.sink.Close(); err != nil {
			closeErr = fmt.Errorf("close %s: %w", p.name, err)
		}
		return errors.Join(flushErr, closeErr)
	})
	p.closeErr = errors.Join(p.failure, err)
	return p.closeErr
}

// Abort can interrupt blocked network I/O without waiting for the publish lock.
func (p *JSONPublisher) Abort() {
	if aborter, ok := p.sink.(interface{ Abort() }); ok {
		aborter.Abort()
	}
}

var _ domain.OperationalLogSink = (*JSONPublisher)(nil)
var _ domain.CapturedEventSink = (*JSONPublisher)(nil)
