package handlers

import (
	"github.com/gojue/ecapture/internal/domain"
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// ProtoEncoder sends events as *pb.Event to an ecaptureQ channel.
// Events that don't implement ToProtobufEvent() are silently skipped.
type ProtoEncoder struct {
	ch chan<- *pb.Event
}

// NewProtoEncoder creates an encoder that sends proto events to ch.
func NewProtoEncoder(ch chan<- *pb.Event) *ProtoEncoder {
	return &ProtoEncoder{ch: ch}
}

func (e *ProtoEncoder) Encode(event domain.Event) error {
	pm, ok := event.(interface{ ToProtobufEvent() *pb.Event })
	if !ok {
		return nil
	}
	select {
	case e.ch <- pm.ToProtobufEvent():
	default:
	}
	return nil
}

func (e *ProtoEncoder) Channel() chan<- *pb.Event { return e.ch }

func (e *ProtoEncoder) Name() string { return "proto" }

func (e *ProtoEncoder) Close() error { return nil }
