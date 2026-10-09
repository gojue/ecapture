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
	"bytes"
	stderrors "errors"
	"fmt"
	"io"
	"sync"
)

// KeylogWriter encodes NSS keylog records over an arbitrary ByteSink. It owns
// the sink and forwards Flush and Close.
type KeylogWriter struct {
	sink     ByteSink
	mu       sync.Mutex
	closed   bool
	closeErr error
}

func (w *KeylogWriter) Name() string {
	return "keylog_writer"
}

func (w *KeylogWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	return w.sink.Flush()
}

func NewKeylogWriter(sink ByteSink) *KeylogWriter {
	return &KeylogWriter{sink: sink}
}

func (w *KeylogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, fmt.Errorf("keylog writer is closed")
	}
	if w.sink == nil {
		return 0, fmt.Errorf("keylog sink is nil")
	}
	record := bytes.TrimRight(p, "\r\n")
	data := make([]byte, len(record)+1)
	copy(data, record)
	data[len(record)] = '\n'
	written, err := w.sink.Write(data)
	if err != nil {
		return 0, err
	}
	if written != len(data) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (w *KeylogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	if w.sink == nil {
		return nil
	}
	w.closeErr = stderrors.Join(w.sink.Flush(), w.sink.Close())
	return w.closeErr
}

var _ ByteSink = (*KeylogWriter)(nil)
