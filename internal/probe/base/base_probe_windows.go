//go:build windows
// +build windows

package base

import (
	"io"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/events"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/output/writers"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// InitDispatcher creates a dispatcher with a text handler wired up.
// Shared by all Windows probes to avoid duplicating the writer/handler setup.
func InitDispatcher(name string, cfg domain.Configuration) (domain.EventDispatcher, error) {
	log := logger.New(nil, cfg.GetDebug()).WithProbe(name)

	dispatcher := events.NewDispatcher(log)
	writerFactory := writers.NewWriterFactory()

	var textWriter writers.OutputWriter
	var err error

	if ew := cfg.GetEventWriter(); ew != nil {
		textWriter = writers.NewIOWriterAdapter(ew, "ecaptureQ")
	} else {
		addr := cfg.GetEventCollectorAddr()
		if addr == "" || addr == "stdout" {
			textWriter = writers.NewLoggerWriter(log)
		} else {
			textWriter, err = writerFactory.CreateWriter(addr, nil)
			if err != nil {
				return nil, errors.Wrap(errors.ErrCodeResourceAllocation, "create text writer", err)
			}
		}
	}

	handler := handlers.NewTextHandler(textWriter, cfg.GetHex())
	if err := dispatcher.Register(handler); err != nil {
		_ = textWriter.Close()
		return nil, errors.Wrap(errors.ErrCodeEventDispatch, "register text handler", err)
	}

	return dispatcher, nil
}

// NewLogger creates a probe-scoped logger.
func NewLogger(name string, debug bool) *logger.Logger {
	return logger.New(nil, debug).WithProbe(name)
}

// CloseDispatcher safely closes a dispatcher.
func CloseDispatcher(d domain.EventDispatcher, log *logger.Logger) {
	if d == nil {
		return
	}
	if err := d.Close(); err != nil && log != nil {
		log.Warn().Err(err).Msg("Failed to close dispatcher")
	}
}

// CloseClosers closes a slice of io.Closer, logging warnings on error.
func CloseClosers(closers []io.Closer, log *logger.Logger) {
	for _, c := range closers {
		if err := c.Close(); err != nil && log != nil {
			log.Warn().Err(err).Msg("Failed to close resource")
		}
	}
}
