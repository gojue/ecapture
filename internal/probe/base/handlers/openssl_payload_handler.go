package handlers

import (
	"io"

	"github.com/gojue/ecapture/internal/domain"
	ep "github.com/gojue/ecapture/pkg/event_processor"
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// OpensslPayloadHandler wraps event_processor.EventProcessor to reuse its
// assembly infrastructure (eventWorker pool, IParser pipeline). It receives
// *pb.Event directly from eventWorker.Display() via ProtoEventCh — no
// marshal/unmarshal round-trip.
type OpensslPayloadHandler struct {
	name string
	proc *ep.EventProcessor
}

// NewOpensslPayloadHandler creates a handler backed by event_processor.
// textOut receives formatted text. protoCh (optional) receives *pb.Event
// for ecaptureQ forwarding.
func NewOpensslPayloadHandler(name string, textOut io.Writer, protoCh chan<- *pb.Event) *OpensslPayloadHandler {
	proc := ep.NewEventProcessor(textOut, false, 0)
	proc.SetProtoEventCh(protoCh)
	go proc.Serve()

	return &OpensslPayloadHandler{name: name, proc: proc}
}

func (h *OpensslPayloadHandler) Handle(event domain.Event) error {
	adapted := adaptEvent(event)
	if adapted == nil {
		return nil
	}
	h.proc.Write(adapted)
	return nil
}

func (h *OpensslPayloadHandler) Name() string { return h.name }

func (h *OpensslPayloadHandler) Close() error {
	err := h.proc.Close()
	return err
}

// assembler is the sub-interface domain events must implement to be
// routed through event_processor.
type assembler interface {
	AsmUUID() string
	Payload() []byte
	ProtoEvent() *pb.Event
}

// adaptEvent converts a domain.Event to an IEventStruct if it implements
// the assembler sub-interface.
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
