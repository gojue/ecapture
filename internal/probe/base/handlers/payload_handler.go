package handlers

import (
	"strings"

	"github.com/gojue/ecapture/internal/domain"
)

// PayloadHandler is a generic handler that passes events through a chain
// of encoders. Each encoder handles one output format/target.
type PayloadHandler struct {
	name     string
	encoders []Encoder
}

// NewPayloadHandler creates a handler that routes events through the given
// encoders in order. The handler's Name() is built from the prefix and
// joined encoder names, e.g. "gotls-text-proto".
func NewPayloadHandler(name string, encoders ...Encoder) *PayloadHandler {
	parts := make([]string, 0, len(encoders)+1)
	parts = append(parts, name)
	for _, enc := range encoders {
		parts = append(parts, enc.Name())
	}
	return &PayloadHandler{name: strings.Join(parts, "-"), encoders: encoders}
}

func (h *PayloadHandler) Handle(event domain.Event) error {
	for _, enc := range h.encoders {
		if err := enc.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func (h *PayloadHandler) Name() string { return h.name }

func (h *PayloadHandler) Encoders() []Encoder { return h.encoders }

func (h *PayloadHandler) Close() error {
	for _, enc := range h.encoders {
		_ = enc.Close()
	}
	return nil
}
