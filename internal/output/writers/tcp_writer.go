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
	"bufio"
	"fmt"
	"net"
	"sync"
)

// TcpWriter writes output to a TCP socket.
type TcpWriter struct {
	conn     net.Conn
	buffered *bufio.Writer
	addr     string
	mu       sync.Mutex
}

// NewTcpWriter creates a new TCP writer by connecting to the specified address.
func NewTcpWriter(addr string, bufferSize int) (*TcpWriter, error) {
	if addr == "" {
		return nil, fmt.Errorf("TCP address cannot be empty")
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to TCP server %s: %w", addr, err)
	}

	tw := &TcpWriter{
		conn: conn,
		addr: addr,
	}

	// Setup buffering if requested
	if bufferSize > 0 {
		tw.buffered = bufio.NewWriterSize(conn, bufferSize)
	}

	return tw, nil
}

// Write writes data to the TCP connection.
func (w *TcpWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buffered != nil {
		return w.buffered.Write(p)
	}

	return w.conn.Write(p)
}

// Close closes the TCP connection.
func (w *TcpWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buffered != nil {
		if err := w.buffered.Flush(); err != nil {
			return err
		}
	}

	if w.conn != nil {
		return w.conn.Close()
	}

	return nil
}

// Name returns the writer name.
func (w *TcpWriter) Name() string {
	return fmt.Sprintf("tcp://%s", w.addr)
}

// Flush flushes any buffered data to the TCP connection.
func (w *TcpWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buffered != nil {
		return w.buffered.Flush()
	}

	return nil
}
