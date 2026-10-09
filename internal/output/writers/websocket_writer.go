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
	stderrors "errors"
	"fmt"
	"io"
	"sync"

	"github.com/gojue/ecapture/v2/pkg/util/ws"
)

// WebSocketWriter writes output to a WebSocket connection.
type WebSocketWriter struct {
	client   *ws.Client
	addr     string
	mu       sync.Mutex
	closed   bool
	closeErr error
}

// NewWebSocketWriter creates a new WebSocket writer by connecting to the specified URL.
func NewWebSocketWriter(url string) (*WebSocketWriter, error) {
	if url == "" {
		return nil, fmt.Errorf("WebSocket URL cannot be empty")
	}

	client := ws.NewClient()
	err := client.Dial(url, "", "http://localhost")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WebSocket server %s: %w", url, err)
	}

	return &WebSocketWriter{
		client: client,
		addr:   url,
	}, nil
}

// Write writes data to the WebSocket connection.
func (w *WebSocketWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, fmt.Errorf("WebSocket sink %s is closed", w.addr)
	}

	n, err = w.client.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Close closes the WebSocket connection.
func (w *WebSocketWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true

	if w.client != nil {
		w.closeErr = stderrors.Join(w.closeErr, w.client.Close())
	}
	return w.closeErr
}

// Name returns the writer name.
func (w *WebSocketWriter) Name() string {
	return w.addr
}

// Flush is a no-op for WebSocket (messages are sent immediately).
func (w *WebSocketWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	return nil
}
