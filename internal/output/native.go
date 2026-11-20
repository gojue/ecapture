// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gojue/ecapture/v2/internal/domain"
	captureerrors "github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/output/writers"
)

// NativeSink publishes the bytes produced by a native keylog/pcapng encoder
// while retaining the original artifact. It owns the artifact sink and borrows
// the process-lifetime publishers. It must be placed after the native encoder:
// packet payloads and secret-event descriptions are not native artifact bytes.
type NativeSink struct {
	sink       writers.ByteSink
	format     domain.CaptureFormat
	publishers []domain.CapturedEventSink
	mu         sync.Mutex
	closed     bool
	failure    error
	closeErr   error
	onFailure  func(error)
}

func NewNativeSink(sink writers.ByteSink, format domain.CaptureFormat, publishers []domain.CapturedEventSink, onFailure ...func(error)) (*NativeSink, error) {
	if sink == nil || isNilValue(sink) {
		return nil, fmt.Errorf("native artifact sink cannot be nil")
	}
	if format != domain.CaptureFormatKeylog && format != domain.CaptureFormatPcapng {
		return nil, fmt.Errorf("unsupported native artifact format %q", format)
	}
	for _, publisher := range publishers {
		if publisher == nil || isNilValue(publisher) {
			return nil, fmt.Errorf("native artifact publisher cannot be nil")
		}
	}
	result := &NativeSink{sink: sink, format: format, publishers: append([]domain.CapturedEventSink(nil), publishers...)}
	if len(onFailure) > 0 {
		result.onFailure = onFailure[0]
	}
	return result, nil
}

func (s *NativeSink) Name() string { return s.sink.Name() }

func (s *NativeSink) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("native artifact sink: %w", io.ErrClosedPipe)
	}
	if s.failure != nil {
		return 0, s.failure
	}
	var failures []error
	n, err := s.sink.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		failures = append(failures, fmt.Errorf("write native artifact: %w", err))
	}
	if len(data) != 0 {
		event := domain.CapturedEventEnvelope{
			Timestamp: time.Now(), Format: s.format, Sensitivity: domain.SensitivitySensitive,
			Payload: append([]byte(nil), data...), OriginalLength: uint32(len(data)),
		}
		for _, publisher := range s.publishers {
			// Probe cancellation precedes final encoder drain. Publishers remain
			// alive until that drain completes and enforce their own I/O bounds.
			if err := publisher.PublishEvent(context.Background(), event); err != nil {
				failures = append(failures, fmt.Errorf("publish native artifact to %s: %w", publisher.Name(), err))
			}
		}
	}
	s.failLocked(errors.Join(failures...))
	if s.failure != nil {
		return n, s.failure
	}
	return len(data), nil
}

func (s *NativeSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.failLocked(s.sink.Flush())
	return s.failure
}

// Fail is also called by the pcapng worker when encoding or a final flush
// fails. Latching the error wakes the probe owner without another packet.
func (s *NativeSink) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(err)
}

func (s *NativeSink) failLocked(err error) {
	if err == nil || s.failure != nil {
		return
	}
	s.failure = &captureerrors.PipelineError{Stage: "native " + string(s.format), Reason: "output failed", Cause: err}
	if s.onFailure != nil {
		s.onFailure(s.failure)
	}
}

func (s *NativeSink) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

func (s *NativeSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.closeErr = errors.Join(s.failure, s.sink.Flush(), s.sink.Close())
	}
	return s.closeErr
}

var _ writers.ByteSink = (*NativeSink)(nil)
