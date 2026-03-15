package writers

import (
	"github.com/gojue/ecapture/internal/logger"
)

type LoggerWriter struct {
	logger *logger.Logger
}

// NewLoggerWriter creates a new stdout writer.
func NewLoggerWriter(logger *logger.Logger) *LoggerWriter {
	return &LoggerWriter{
		logger: logger,
	}
}

// Write writes data to stdout.
func (w *LoggerWriter) Write(p []byte) (n int, err error) {
	w.logger.Info().Msg(string(p))
	return len(p), nil
}

// Close is a no-op for stdout.
func (w *LoggerWriter) Close() error {
	return nil
}

// Name returns the writer name.
func (w *LoggerWriter) Name() string {
	return "LoggerWriter"
}

// Flush is a no-op for stdout (unbuffered).
func (w *LoggerWriter) Flush() error {
	return nil
}
