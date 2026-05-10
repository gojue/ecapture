package handlers

import "github.com/gojue/ecapture/internal/domain"

// Encoder converts a domain.Event to a specific wire format and writes it
// to a destination the encoder owns. Each encoder handles one format/target
// pair; multiple encoders compose into a single Handler for multi-output.
type Encoder interface {
	Encode(event domain.Event) error
	Name() string
	Close() error
}
