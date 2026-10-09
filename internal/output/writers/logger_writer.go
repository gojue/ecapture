package writers

import (
	"fmt"
	"sync"

	"github.com/gojue/ecapture/v2/internal/logger"
)

type LoggerWriter struct {
	logger *logger.Logger
	mu     sync.Mutex
	closed bool
}

// NewLoggerWriter creates a new stdout writer.
func NewLoggerWriter(logger *logger.Logger) *LoggerWriter {
	return &LoggerWriter{
		logger: logger,
	}
}

// Write writes data to stdout.
func (w *LoggerWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, fmt.Errorf("logger writer is closed")
	}
	w.logger.Info().Msg(string(p))
	return len(p), nil
}

// Close is a no-op for stdout.
func (w *LoggerWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

// Name returns the writer name.
func (w *LoggerWriter) Name() string {
	return "LoggerWriter"
}

// Flush is a no-op for stdout (unbuffered).
func (w *LoggerWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return nil
}
