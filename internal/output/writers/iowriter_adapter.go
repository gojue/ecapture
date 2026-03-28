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
	"io"
)

// IOWriterAdapter adapts an io.Writer to the OutputWriter interface.
type IOWriterAdapter struct {
	writer io.Writer
	name   string
}

// NewIOWriterAdapter creates a new OutputWriter wrapping an io.Writer.
func NewIOWriterAdapter(w io.Writer, name string) *IOWriterAdapter {
	return &IOWriterAdapter{
		writer: w,
		name:   name,
	}
}

// Write writes data to the underlying writer.
func (a *IOWriterAdapter) Write(p []byte) (n int, err error) {
	return a.writer.Write(p)
}

// Close closes the underlying writer if it implements io.Closer.
func (a *IOWriterAdapter) Close() error {
	if closer, ok := a.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Name returns the writer name.
func (a *IOWriterAdapter) Name() string {
	return a.name
}

// Flush is a no-op for generic io.Writer.
func (a *IOWriterAdapter) Flush() error {
	return nil
}
