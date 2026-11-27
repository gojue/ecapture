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
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/v2/pkg/util/roratelog"
)

// FileWriter writes to a local file or FIFO; rotation is regular-file only.
type FileWriter struct {
	file         *os.File
	rotateLog    *roratelog.Logger
	buffered     *bufio.Writer
	path         string
	useRotate    bool
	mu           sync.Mutex
	closed       bool
	closeErr     error
	fifo         bool
	writeErr     error
	writeTimeout time.Duration
}

// FileWriterConfig configures file writer options.
type FileWriterConfig struct {
	Path         string        // File path
	EnableRotate bool          // Enable log rotation
	MaxSizeMB    int           // Maximum file size in MB (for rotation)
	MaxInterval  time.Duration // Maximum time interval (for rotation)
	BufferSize   int           // Buffer size in bytes (0 = unbuffered)
	Truncate     bool          // Truncate file on open (instead of append)
	Permissions  os.FileMode   // File permissions (zero defaults to 0644)
}

// NewFileWriter creates a new file writer.
func NewFileWriter(config FileWriterConfig) (*FileWriter, error) {
	if config.Path == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	fw := &FileWriter{
		path:      config.Path,
		useRotate: config.EnableRotate,
	}

	if config.EnableRotate && (config.MaxSizeMB > 0 || config.MaxInterval > 0) {
		if info, err := os.Stat(config.Path); err == nil && info.Mode()&os.ModeNamedPipe != 0 {
			return nil, fmt.Errorf("FIFO output does not support rotation: %s", config.Path)
		}
		// Use rotating file logger
		fw.rotateLog = &roratelog.Logger{
			Filename:    config.Path,
			MaxSize:     config.MaxSizeMB,
			MaxInterval: config.MaxInterval,
			LocalTime:   true,
		}
		return fw, nil
	}

	// Nonblocking open fails promptly when a FIFO has no reader and lets Go's
	// poller enforce write deadlines. It does not change regular-file I/O.
	flags := os.O_CREATE | os.O_WRONLY | unix.O_NONBLOCK
	if config.Truncate {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}
	permissions := config.Permissions
	if permissions == 0 {
		permissions = 0644
	}
	file, err := os.OpenFile(config.Path, flags, permissions)
	if err != nil {
		if stderrors.Is(err, unix.ENXIO) {
			return nil, fmt.Errorf("open FIFO %s: start a reader before capture: %w", config.Path, err)
		}
		return nil, fmt.Errorf("failed to open file %s: %w", config.Path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	fw.file = file
	fw.fifo = info.Mode()&os.ModeNamedPipe != 0
	fw.writeTimeout = 5 * time.Second

	// Setup buffering if requested
	if config.BufferSize > 0 {
		fw.buffered = bufio.NewWriterSize(file, config.BufferSize)
	}

	return fw, nil
}

// Write writes data to the file.
func (w *FileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, fmt.Errorf("file sink %s is closed", w.path)
	}
	return w.writeLocked(p)
}

func (w *FileWriter) writeLocked(p []byte) (n int, err error) {
	if err := w.prepareWriteLocked(); err != nil {
		return 0, err
	}
	defer func() {
		if w.fifo && err != nil {
			w.writeErr = err
		}
	}()
	if w.rotateLog != nil {
		n, err = w.rotateLog.Write(p)
	} else if w.buffered != nil {
		n, err = w.buffered.Write(p)
	} else {
		n, err = w.file.Write(p)
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Close closes the file and releases resources.
func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true

	flushErr := w.flushLocked()
	var closeErr error
	if w.rotateLog != nil {
		closeErr = w.rotateLog.Close()
	} else if w.file != nil {
		closeErr = w.file.Close()
	}
	w.closeErr = stderrors.Join(flushErr, closeErr)
	return w.closeErr
}

// Name returns the writer name.
func (w *FileWriter) Name() string {
	return fmt.Sprintf("file:%s", w.path)
}

// Flush drains buffered data and syncs regular files. FIFOs cannot be synced.
func (w *FileWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	return w.flushLocked()
}

func (w *FileWriter) flushLocked() error {
	if err := w.prepareWriteLocked(); err != nil {
		return err
	}
	if w.buffered != nil {
		if err := w.buffered.Flush(); err != nil {
			if w.fifo {
				w.writeErr = err
			}
			return err
		}
	}

	if w.file != nil && !w.fifo {
		return w.file.Sync()
	}

	return nil
}

// A failed FIFO stream cannot be resumed safely (a pcapng block or JSON line
// may already be partial). Preserve the first error through flush and close.
func (w *FileWriter) prepareWriteLocked() error {
	if !w.fifo {
		return nil
	}
	if w.writeErr == nil {
		w.writeErr = w.file.SetWriteDeadline(time.Now().Add(w.writeTimeout))
	}
	return w.writeErr
}
