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
	"io"
	"os"
	"sync"
)

// StdoutWriter writes output to stdout.
type StdoutWriter struct {
	mu     sync.Mutex
	out    io.Writer
	name   string
	closed bool
}

// NewStdoutWriter creates a new stdout writer.
func NewStdoutWriter() *StdoutWriter {
	return newStandardStreamWriter(os.Stdout, "stdout")
}

// NewStderrWriter creates an operational console sink. Captured event stdout
// and operational stderr are independently constructed streams.
func NewStderrWriter() *StdoutWriter {
	return newStandardStreamWriter(os.Stderr, "stderr")
}

func newStandardStreamWriter(out io.Writer, name string) *StdoutWriter {
	return &StdoutWriter{out: out, name: name}
}

// Write writes data to stdout.
func (w *StdoutWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, fmt.Errorf("%s sink is closed", w.name)
	}
	n, err = w.out.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Close is a no-op for stdout.
func (w *StdoutWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

// Name returns the writer name.
func (w *StdoutWriter) Name() string {
	return w.name
}

// Flush is a no-op for standard streams. Calling fsync on a terminal or pipe
// returns platform-specific errors and does not provide additional durability.
func (w *StdoutWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return nil
}
