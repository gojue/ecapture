// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/v2/internal/domain"
)

type operationalSinkStub struct {
	mu      sync.Mutex
	records []domain.OperationalLogRecord
	err     error
	closed  int
}

func (s *operationalSinkStub) PublishLog(_ context.Context, record domain.OperationalLogRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
	return s.err
}

func (s *operationalSinkStub) Name() string { return "stub" }
func (s *operationalSinkStub) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func TestOperationalLogWriterPropagatesAndWrapsErrors(t *testing.T) {
	publishErr := errors.New("publish failed")
	sink := &operationalSinkStub{err: publishErr}
	writer, err := NewOperationalLogWriter(sink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.WriteLevel(zerolog.WarnLevel, []byte("runtime")); !errors.Is(err, publishErr) {
		t.Fatalf("WriteLevel() error = %v", err)
	}
	if sink.closed != 0 {
		t.Fatal("logging adapter closed its borrowed typed publisher")
	}
}

func TestOperationalLogWriterConcurrentDelivery(t *testing.T) {
	sink := &operationalSinkStub{}
	writer, err := NewOperationalLogWriter(sink)
	if err != nil {
		t.Fatal(err)
	}
	const count = 128
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, writeErr := writer.WriteLevel(zerolog.InfoLevel, []byte("runtime")); writeErr != nil {
				t.Error(writeErr)
			}
		}()
	}
	wg.Wait()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.records) != count {
		t.Fatalf("delivered records = %d, want %d", len(sink.records), count)
	}
}

func TestNewOperationalLogWriterRejectsTypedNil(t *testing.T) {
	var sink *operationalSinkStub
	if _, err := NewOperationalLogWriter(sink); err == nil {
		t.Fatal("NewOperationalLogWriter() accepted a typed nil sink")
	}
}
