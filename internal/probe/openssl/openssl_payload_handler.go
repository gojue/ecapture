package openssl

import (
	"io"
	"strings"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	ep "github.com/gojue/ecapture/pkg/event_processor"
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// PayloadHandler wraps event_processor.EventProcessor for SSL stream
// assembly. It receives *pb.Event from eventWorker.Display() via
// ProtoEventCh — no marshal/unmarshal round-trip.
type PayloadHandler struct {
	name string
	proc *ep.EventProcessor
}

// NewPayloadHandler creates a handler backed by event_processor.
// encoders provide both naming and output config:
// TextEncoder → text, ProtoEncoder → ecaptureQ.
func NewPayloadHandler(name string, encoders ...handlers.Encoder) *PayloadHandler {
	var textOut io.Writer
	var protoCh chan<- *pb.Event
	for _, enc := range encoders {
		switch e := enc.(type) {
		case *handlers.TextEncoder:
			textOut = e.Writer()
		case *handlers.ProtoEncoder:
			protoCh = e.Channel()
		}
	}

	proc := ep.NewEventProcessor(textOut, false, 0)
	proc.SetProtoEventCh(protoCh)
	go proc.Serve()

	parts := []string{name}
	for _, enc := range encoders {
		parts = append(parts, enc.Name())
	}

	return &PayloadHandler{name: strings.Join(parts, "-"), proc: proc}
}

func (h *PayloadHandler) Handle(event domain.Event) error {
	adapted := adaptEvent(event)
	if adapted == nil {
		return nil
	}
	h.proc.Write(adapted)
	return nil
}

func (h *PayloadHandler) Name() string { return h.name }

func (h *PayloadHandler) Close() error { return h.proc.Close() }

type assembler interface {
	AsmUUID() string
	Payload() []byte
	ProtoEvent() *pb.Event
}

func adaptEvent(event domain.Event) ep.IEventStruct {
	a, ok := event.(assembler)
	if !ok {
		return nil
	}
	return &eventAdapter{event: event, a: a}
}

type eventAdapter struct {
	event domain.Event
	a     assembler
}

func (e *eventAdapter) GetUUID() string            { return e.a.AsmUUID() }
func (e *eventAdapter) Payload() []byte            { return e.a.Payload() }
func (e *eventAdapter) EventType() ep.Type         { return ep.TypeOutput }
func (e *eventAdapter) Base() ep.Base              { return ep.Base{} }
func (e *eventAdapter) ToProtobufEvent() *pb.Event { return e.a.ProtoEvent() }
func (e *eventAdapter) Clone() ep.IEventStruct     { return e }
