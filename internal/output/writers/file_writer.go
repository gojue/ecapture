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
	"os"
	"time"

	"github.com/gojue/ecapture/pkg/util/roratelog"
)

// FileWriter writes output to a local file with optional rotation support.
type FileWriter struct {
	file      *os.File
	rotateLog *roratelog.Logger
	buffered  *bufio.Writer
	path      string
	useRotate bool
}

// FileWriterConfig configures file writer options.
type FileWriterConfig struct {
	Path         string        // File path
	EnableRotate bool          // Enable log rotation
	MaxSizeMB    int           // Maximum file size in MB (for rotation)
	MaxInterval  time.Duration // Maximum time interval (for rotation)
	BufferSize   int           // Buffer size in bytes (0 = unbuffered)
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
		// Use rotating file logger
		fw.rotateLog = &roratelog.Logger{
			Filename:    config.Path,
			MaxSize:     config.MaxSizeMB,
			MaxInterval: config.MaxInterval,
			LocalTime:   true,
		}
		return fw, nil
	}

	// Use regular file
	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", config.Path, err)
	}

	fw.file = file

	// Setup buffering if requested
	if config.BufferSize > 0 {
		fw.buffered = bufio.NewWriterSize(file, config.BufferSize)
	}

	return fw, nil
}

// Write writes data to the file.
func (w *FileWriter) Write(p []byte) (n int, err error) {
	if w.rotateLog != nil {
		return w.rotateLog.Write(p)
	}

	if w.buffered != nil {
		return w.buffered.Write(p)
	}

	return w.file.Write(p)
}

// Close closes the file and releases resources.
func (w *FileWriter) Close() error {
	err := w.Flush()
	if err != nil {
		return err
	}

	if w.rotateLog != nil {
		return w.rotateLog.Close()
	}

	if w.buffered != nil {
		if err := w.buffered.Flush(); err != nil {
			return err
		}
	}

	if w.file != nil {
		return w.file.Close()
	}

	return nil
}

// Name returns the writer name.
func (w *FileWriter) Name() string {
	return fmt.Sprintf("file:%s", w.path)
}

// Flush flushes any buffered data to disk.
func (w *FileWriter) Flush() error {
	if w.buffered != nil {
		return w.buffered.Flush()
	}

	if w.file != nil {
		return w.file.Sync()
	}

	return nil
}
