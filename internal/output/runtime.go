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
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/logger"
)

// RuntimeDependencies contains process-lifetime output dependencies that must
// not be serialized into probe configuration. The CLI owns these dependencies;
// probes and handlers borrow them.
type RuntimeDependencies struct {
	OperationalLogger *logger.Logger
	EventSinks        []domain.CapturedEventSink
}

// Clone returns a shallow dependency copy with an independent sink slice. The
// contained logger and publishers remain borrowed process-lifetime objects.
func (d *RuntimeDependencies) Clone() *RuntimeDependencies {
	if d == nil {
		return nil
	}
	clone := &RuntimeDependencies{OperationalLogger: d.OperationalLogger}
	clone.EventSinks = append(clone.EventSinks, d.EventSinks...)
	return clone
}

// OperationalLogWriter adapts a typed operational publisher to zerolog's edge
// interfaces. It does not own or close the publisher.
type OperationalLogWriter struct {
	sink domain.OperationalLogSink
	mu   sync.Mutex
}

func NewOperationalLogWriter(sink domain.OperationalLogSink) (*OperationalLogWriter, error) {
	if sink == nil || isNilValue(sink) {
		return nil, fmt.Errorf("operational log sink cannot be nil")
	}
	return &OperationalLogWriter{sink: sink}, nil
}

func isNilValue(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (w *OperationalLogWriter) Write(p []byte) (int, error) {
	return w.WriteLevel(zerolog.NoLevel, p)
}

func (w *OperationalLogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	record := domain.OperationalLogRecord{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   string(append([]byte(nil), p...)),
	}
	if err := w.sink.PublishLog(context.Background(), record); err != nil {
		return 0, fmt.Errorf("publish operational log to %s: %w", w.sink.Name(), err)
	}
	return len(p), nil
}

var _ zerolog.LevelWriter = (*OperationalLogWriter)(nil)
