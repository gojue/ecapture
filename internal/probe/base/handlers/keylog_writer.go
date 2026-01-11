package handlers

// TcpWriter writes output to a TCP socket.
type PcapKeylogWriter struct {
	*PcapWriter
}

func (w *PcapKeylogWriter) Name() string {
	return "pcap_keylog_writer"
}

func (w *PcapKeylogWriter) Flush() error {
	//w.PcapWriter.Flush()
	return nil
}

func NewPcapKeylogWriter(pw *PcapWriter) *PcapKeylogWriter {
	return &PcapKeylogWriter{
		PcapWriter: pw,
	}
}

func (w *PcapKeylogWriter) Write(p []byte) (n int, err error) {
	return len(p), w.PcapWriter.WriteKeyLog(p)
}
