package handlers

import (
	"io"

	"github.com/gojue/ecapture/internal/domain"
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// GoTlsPayloadHandler handles gotls events which are self-contained
// (one eBPF event = one complete TLS record, no assembly needed).
// It formats text output via event.String() and optionally sends
// protobuf events to ecaptureQ.
type GoTlsPayloadHandler struct {
	name    string
	textOut io.Writer
	protoCh chan<- *pb.Event
}

// NewGoTlsPayloadHandler creates a handler for gotls events.
// protoCh is optional (nil disables proto output).
func NewGoTlsPayloadHandler(name string, textOut io.Writer, protoCh chan<- *pb.Event) *GoTlsPayloadHandler {
	return &GoTlsPayloadHandler{name: name, textOut: textOut, protoCh: protoCh}
}

func (h *GoTlsPayloadHandler) Handle(event domain.Event) error {
	if h.protoCh != nil {
		if pm, ok := event.(interface{ ToProtobufEvent() *pb.Event }); ok {
			select {
			case h.protoCh <- pm.ToProtobufEvent():
			default:
			}
		}
	} else {
		output := event.String()
		if output != "" {
			if output[len(output)-1] != '\n' {
				output += "\n"
			}
			h.textOut.Write([]byte(output))
		}
	}
	return nil
}

func (h *GoTlsPayloadHandler) Name() string { return h.name }

func (h *GoTlsPayloadHandler) Close() error {
	if closer, ok := h.textOut.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
