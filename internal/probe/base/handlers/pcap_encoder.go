package handlers

import (
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/output/writers"
)

// PacketEvent is implemented by events carrying raw network packets.
type PacketEvent interface {
	domain.Event
	GetTimestamp() uint64
	GetPacketData() []byte
}

// PcapEncoder writes network packet events to a pcapng file.
type PcapEncoder struct {
	pcapWriter *writers.PcapWriter
}

// NewPcapEncoder creates an encoder that writes packets to w.
func NewPcapEncoder(pcapWriter *writers.PcapWriter) *PcapEncoder {
	return &PcapEncoder{pcapWriter: pcapWriter}
}

func (e *PcapEncoder) Encode(event domain.Event) error {
	pktEvent, ok := event.(PacketEvent)
	if !ok {
		return nil
	}
	data := pktEvent.GetPacketData()
	if len(data) == 0 {
		return nil
	}
	return e.pcapWriter.WritePacket(data, time.Unix(0, int64(pktEvent.GetTimestamp())))
}

func (e *PcapEncoder) Name() string { return "pcap" }

func (e *PcapEncoder) Close() error {
	if e.pcapWriter != nil {
		return e.pcapWriter.Close()
	}
	return nil
}

// PcapWriter returns the underlying pcap writer (for keylog embedding).
func (e *PcapEncoder) PcapWriter() *writers.PcapWriter {
	return e.pcapWriter
}
