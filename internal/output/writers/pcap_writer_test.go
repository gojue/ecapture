package writers

import (
	"testing"
	"time"
)

func TestWritePacketWaitsForQueueCapacity(t *testing.T) {
	packetChan := make(chan *TcPacket, 1)
	packetChan <- &TcPacket{}
	pw := &PcapWriter{packetChan: packetChan}

	data := []byte{0x45, 0x00, 0x00, 0x3c}
	timestamp := time.Unix(123, 456)
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- pw.WritePacket(data, timestamp)
	}()

	select {
	case err := <-writeResult:
		t.Fatalf("WritePacket returned before the queue had capacity: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	<-packetChan

	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("WritePacket returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WritePacket did not finish after queue capacity became available")
	}

	packet := <-packetChan
	if string(packet.data) != string(data) {
		t.Errorf("packet data = %v, want %v", packet.data, data)
	}
	if !packet.ci.Timestamp.Equal(timestamp) {
		t.Errorf("packet timestamp = %v, want %v", packet.ci.Timestamp, timestamp)
	}
}
