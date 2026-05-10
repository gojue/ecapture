package handlers

import (
	"io"

	"github.com/gojue/ecapture/internal/domain"
)

// TextEncoder formats events via String() and writes to an io.Writer.
type TextEncoder struct {
	writer io.Writer
}

// NewTextEncoder creates an encoder that writes event text to w.
func NewTextEncoder(w io.Writer) *TextEncoder {
	return &TextEncoder{writer: w}
}

func (e *TextEncoder) Encode(event domain.Event) error {
	s := event.String()
	if s == "" {
		return nil
	}
	if s[len(s)-1] != '\n' {
		s += "\n"
	}
	_, err := e.writer.Write([]byte(s))
	return err
}

func (e *TextEncoder) Writer() io.Writer { return e.writer }

func (e *TextEncoder) Name() string { return "text" }

func (e *TextEncoder) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
