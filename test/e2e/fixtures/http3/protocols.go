// These loopback peers never configure a KeyLogWriter. Their exact wire bytes
// and live event checks exercise the SDK through eCapture's real GoTLS probe.
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func protocolFixture(mode, protocol, address, ready, token, events, release, phase string, version quic.Version) error {
	if mode == "verify" {
		return verifyProtocol(events, protocol, token, phase)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cert, err := certificate()
	if err != nil {
		return err
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS13} // Ephemeral loopback certificate.
	if strings.HasPrefix(protocol, "doh") || strings.HasPrefix(protocol, "sse") || protocol == "grpc" {
		return httpProtocol(ctx, mode, protocol, address, ready, token, release, version, serverTLS, clientTLS)
	}
	if protocol == "doq" || protocol == "datagram" {
		return quicProtocol(ctx, mode, protocol, address, ready, token, version, serverTLS, clientTLS)
	}
	steps, err := wireSteps(protocol, token)
	if err != nil {
		return err
	}
	var conn net.Conn
	if mode == "server" {
		listener, listenErr := net.Listen("tcp4", address)
		if listenErr != nil {
			return listenErr
		}
		defer listener.Close()
		if err := os.WriteFile(ready, []byte(listener.Addr().String()), 0o600); err != nil {
			return err
		}
		conn, err = listener.Accept()
	} else if mode == "client" {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	} else {
		return fmt.Errorf("unknown fixture mode %q", mode)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if protocol == "smtp" || protocol == "connect" {
		if err := exchangeSteps(conn, mode, upgradePrelude(protocol)); err != nil {
			return err
		}
	}
	var secure *tls.Conn
	if mode == "server" {
		secure = tls.Server(conn, serverTLS)
	} else {
		secure = tls.Client(conn, clientTLS)
	}
	defer secure.Close()
	if protocol == "https-connect" {
		if err := exchangeSteps(secure, mode, upgradePrelude(protocol)); err != nil {
			return err
		}
		if mode == "server" {
			secure = tls.Server(secure, serverTLS)
		} else {
			secure = tls.Client(secure, clientTLS)
		}
		defer secure.Close()
	}
	return exchangeSteps(secure, mode, steps)
}

type wireStep struct {
	server bool
	data   []byte
}

func exchangeSteps(conn io.ReadWriter, mode string, steps []wireStep) error {
	for _, step := range steps {
		if step.server == (mode == "server") {
			// Split length prefixes and message bodies over separate TLS records.
			for _, part := range [][]byte{step.data[:1], step.data[1:]} {
				if _, err := conn.Write(part); err != nil {
					return err
				}
			}
		} else if err := readExpected(conn, step.data); err != nil {
			return err
		}
	}
	return nil
}

func readExpected(reader io.Reader, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("peer payload mismatch")
	}
	return nil
}

func upgradePrelude(protocol string) []wireStep {
	if protocol != "smtp" {
		return []wireStep{{false, []byte("CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")}, {true, []byte("HTTP/1.1 200 Connection established\r\n\r\n")}}
	}
	return []wireStep{
		{true, []byte("220 localhost ESMTP\r\n")}, {false, []byte("EHLO localhost\r\n")},
		{true, []byte("250-localhost\r\n250 STARTTLS\r\n")}, {false, []byte("STARTTLS\r\n")},
		{true, []byte("220 Ready for TLS\r\n")},
	}
}

func wireSteps(protocol, token string) ([]wireStep, error) {
	switch protocol {
	case "dot":
		q1, a1 := dnsWire(token, 1, false)
		q2, a2 := dnsWire(token, 2, false)
		return []wireStep{{false, append(lengthPrefix(q1), lengthPrefix(q2)...)}, {true, append(lengthPrefix(a2), lengthPrefix(a1)...)}}, nil
	case "smtp", "connect", "https-connect":
		return []wireStep{{false, []byte(token + "_CLIENT")}, {true, []byte(token + "_SERVER")}}, nil
	case "websocket":
		client, server := websocketMessages(token)
		clientCompressed, serverCompressed := websocketCompress(client), websocketCompress(server)
		request, response := websocketUpgrade()
		return []wireStep{
			{false, request}, {true, response},
			{false, websocketFrame(0x41, clientCompressed[:2], true)},
			{false, websocketFrame(0x89, []byte("client-ping"), true)},
			{true, websocketFrame(0x8a, []byte("client-ping"), false)},
			{false, websocketFrame(0x80, clientCompressed[2:], true)},
			{true, websocketFrame(0x42, serverCompressed[:2], false)},
			{true, websocketFrame(0x89, []byte("server-ping"), false)},
			{false, websocketFrame(0x8a, []byte("server-ping"), true)},
			{true, websocketFrame(0x80, serverCompressed[2:], false)},
			{false, websocketFrame(0x88, []byte{3, 232}, true)},
			{true, websocketFrame(0x88, []byte{3, 232}, false)},
		}, nil
	case "mqtt":
		connect := append([]byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 30}, lengthPrefix([]byte(token))...)
		return []wireStep{
			{false, mqttPacket(0x10, connect)}, {true, []byte{0x20, 2, 0, 0}},
			{false, mqttPacket(0x30, append(lengthPrefix([]byte("fixture/client")), []byte(token+"_CLIENT")...))},
			{true, mqttPacket(0x30, append(lengthPrefix([]byte("fixture/server")), []byte(token+"_SERVER")...))},
			{false, []byte{0xc0, 0}}, {true, []byte{0xd0, 0}}, {false, []byte{0xe0, 0}},
		}, nil
	case "redis":
		value := append([]byte{0, 0xff}, []byte(token)...)
		return []wireStep{
			{false, respArray([]byte("HELLO"), []byte("3"))}, {true, []byte("%1\r\n+proto\r\n:3\r\n")},
			{false, respArray([]byte("SET"), []byte("key"), value)}, {false, respArray([]byte("GET"), []byte("key"))},
			{true, []byte("+OK\r\n")}, {true, []byte("|1\r\n+ttl\r\n:10\r\n")},
			{true, []byte(">2\r\n+invalidate\r\n*1\r\n$3\r\nkey\r\n")}, {true, respBulk(value)},
		}, nil
	default:
		return nil, fmt.Errorf("unknown protocol fixture %q", protocol)
	}
}

func lengthPrefix(data []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...)
}

func websocketUpgrade() ([]byte, []byte) {
	extension := "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n"
	request := "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" + extension + "\r\n"
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" + extension + "\r\n"
	return []byte(request), []byte(response)
}

func websocketMessages(token string) ([]byte, []byte) {
	return []byte(token + "_CLIENT"), append([]byte{0, 0xff}, []byte(token+"_SERVER")...)
}

func websocketCompress(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(data)
	_ = w.Flush()
	// RFC 7692 removes the empty sync-flush block from each message.
	result := append([]byte(nil), buf.Bytes()[:buf.Len()-4]...)
	_ = w.Close()
	return result
}

func websocketFrame(first byte, data []byte, masked bool) []byte {
	frame := []byte{first, byte(len(data))}
	if !masked {
		return append(frame, data...)
	}
	frame[1] |= 0x80
	mask := [4]byte{1, 2, 3, 4}
	frame = append(frame, mask[:]...)
	for i, b := range data {
		frame = append(frame, b^mask[i%4])
	}
	return frame
}

func mqttPacket(first byte, body []byte) []byte {
	packet := []byte{first}
	for n := len(body); ; n /= 128 {
		b := byte(n % 128)
		if n >= 128 {
			b |= 128
		}
		packet = append(packet, b)
		if n < 128 {
			return append(packet, body...)
		}
	}
}

func respBulk(data []byte) []byte {
	return append(append([]byte(fmt.Sprintf("$%d\r\n", len(data))), data...), '\r', '\n')
}

func respArray(values ...[]byte) []byte {
	data := []byte(fmt.Sprintf("*%d\r\n", len(values)))
	for _, value := range values {
		data = append(data, respBulk(value)...)
	}
	return data
}

func dnsWire(token string, index byte, zeroID bool) ([]byte, []byte) {
	query := []byte{0, index, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if zeroID {
		query[1] = 0
	}
	name := fmt.Sprintf("%s-%d.example", strings.ToLower(token), index)
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	answer := append([]byte(nil), query...)
	answer[2], answer[3], answer[7] = 0x81, 0x80, 1
	answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	return query, answer
}

func httpProtocol(ctx context.Context, mode, protocol, address, ready, token, release string, version quic.Version, serverTLS, clientTLS *tls.Config) error {
	h3 := strings.HasSuffix(protocol, "3")
	h2 := strings.HasSuffix(protocol, "2") || protocol == "grpc"
	if mode == "server" {
		handler := protocolHandler(protocol, token, release)
		if h3 {
			listener, err := net.ListenPacket("udp4", address)
			if err != nil {
				return err
			}
			defer listener.Close()
			server := &http3.Server{TLSConfig: serverTLS, QUICConfig: &quic.Config{Versions: []quic.Version{version}}, Handler: handler}
			defer server.Close()
			if err := os.WriteFile(ready, []byte(listener.LocalAddr().String()), 0o600); err != nil {
				return err
			}
			return server.Serve(listener)
		}
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			return err
		}
		defer listener.Close()
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, TLSConfig: serverTLS}
		if h2 {
			if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
				return err
			}
		} else {
			serverTLS.NextProtos = []string{"http/1.1"}
		}
		defer server.Close()
		if err := os.WriteFile(ready, []byte(listener.Addr().String()), 0o600); err != nil {
			return err
		}
		return server.Serve(tls.NewListener(listener, serverTLS))
	}
	if mode != "client" {
		return fmt.Errorf("unknown fixture mode %q", mode)
	}
	var transport http.RoundTripper
	switch {
	case h3:
		t := &http3.Transport{TLSClientConfig: clientTLS, QUICConfig: &quic.Config{Versions: []quic.Version{version}}}
		defer t.Close()
		transport = t
	case h2:
		t := &http2.Transport{TLSClientConfig: clientTLS}
		defer t.CloseIdleConnections()
		transport = t
	default:
		t := &http.Transport{TLSClientConfig: clientTLS}
		defer t.CloseIdleConnections()
		transport = t
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	count := 1
	if strings.HasPrefix(protocol, "doh") {
		count = 2
	}
	for i := 1; i <= count; i++ {
		method, target := http.MethodGet, "https://"+address+"/events"
		var requestBody, want []byte
		if strings.HasPrefix(protocol, "doh") {
			requestBody, want = dnsWire(token, byte(i), false)
			target = "https://" + address + "/dns-query"
			if i == 1 {
				target += "?dns=" + base64.RawURLEncoding.EncodeToString(requestBody)
				requestBody = nil
			} else {
				method = http.MethodPost
			}
		} else if protocol == "grpc" {
			method = http.MethodPost
			requestBody = grpcFrame([]byte(token+"_CLIENT"), false)
			want = append(grpcFrame(nil, false), grpcFrame([]byte(token+"_SERVER"), true)...)
		} else {
			want = []byte(sseData(token, 1) + sseData(token, 2))
		}
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(requestBody))
		if err != nil {
			return err
		}
		if strings.HasPrefix(protocol, "doh") {
			req.Header.Set("Content-Type", "application/dns-message")
		} else if protocol == "grpc" {
			req.Header.Set("Content-Type", "application/grpc")
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		var reader io.Reader = response.Body
		if response.Header.Get("Content-Encoding") == "gzip" {
			z, err := gzip.NewReader(reader)
			if err != nil {
				response.Body.Close()
				return err
			}
			defer z.Close()
			reader = z
		}
		data, err := io.ReadAll(io.LimitReader(reader, 1<<20))
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(data, want) ||
			(h3 && response.ProtoMajor != 3) || (h2 && response.ProtoMajor != 2) || (!h3 && !h2 && response.ProtoMajor != 1) {
			return fmt.Errorf("%s peer response mismatch", protocol)
		}
		if protocol == "grpc" && response.Trailer.Get("Grpc-Status") != "0" {
			return fmt.Errorf("gRPC status missing")
		}
	}
	return nil
}

func protocolHandler(protocol, token, release string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(protocol, "doh") {
			index := byte(1)
			var data []byte
			var err error
			if r.Method == http.MethodGet {
				data, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			} else {
				index = 2
				data, err = io.ReadAll(io.LimitReader(r.Body, 65536))
			}
			query, answer := dnsWire(token, index, false)
			if err != nil || !bytes.Equal(data, query) {
				http.Error(w, "DNS request mismatch", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(answer)
			return
		}
		if protocol == "grpc" {
			data, err := io.ReadAll(io.LimitReader(r.Body, 65536))
			if err != nil || r.ProtoMajor != 2 || !bytes.Equal(data, grpcFrame([]byte(token+"_CLIENT"), false)) {
				http.Error(w, "gRPC request mismatch", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Encoding", "gzip")
			w.Header().Set("Trailer", "Grpc-Status")
			_, _ = w.Write(append(grpcFrame(nil, false), grpcFrame([]byte(token+"_SERVER"), true)...))
			w.(http.Flusher).Flush()
			if waitRelease(r.Context(), release) == nil {
				w.Header().Set("Grpc-Status", "0")
			}
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Trailer", "X-Ecapture-Final")
		var output io.Writer = w
		var compressed *gzip.Writer
		if protocol == "sse-gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			compressed = gzip.NewWriter(w)
			output = compressed
		}
		_, _ = io.WriteString(output, sseData(token, 1))
		if compressed != nil {
			_ = compressed.Flush()
		}
		w.(http.Flusher).Flush()
		if waitRelease(r.Context(), release) != nil {
			return
		}
		_, _ = io.WriteString(output, sseData(token, 2))
		if compressed != nil {
			_ = compressed.Close()
		}
		w.Header().Set("X-Ecapture-Final", "done")
	})
}

func waitRelease(ctx context.Context, path string) error {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("live event verification did not release response")
		case <-ticker.C:
		}
	}
}

func sseData(token string, index int) string {
	return fmt.Sprintf("id: %d\nevent: update\nretry: 100\ndata: %s_%d\n\n", index, token, index)
}

func grpcFrame(data []byte, compressed bool) []byte {
	flag := byte(0)
	if compressed {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		_, _ = writer.Write(data)
		_ = writer.Close()
		data = buf.Bytes()
		flag = 1
	}
	return append(binary.BigEndian.AppendUint32([]byte{flag}, uint32(len(data))), data...)
}

func quicProtocol(ctx context.Context, mode, protocol, address, ready, token string, version quic.Version, serverTLS, clientTLS *tls.Config) error {
	serverTLS.NextProtos, clientTLS.NextProtos = []string{protocol}, []string{protocol}
	config := &quic.Config{Versions: []quic.Version{version}, EnableDatagrams: protocol == "datagram"}
	var conn *quic.Conn
	var err error
	if mode == "server" {
		listener, listenErr := quic.ListenAddr(address, serverTLS, config)
		if listenErr != nil {
			return listenErr
		}
		defer listener.Close()
		if err := os.WriteFile(ready, []byte(listener.Addr().String()), 0o600); err != nil {
			return err
		}
		conn, err = listener.Accept(ctx)
	} else if mode == "client" {
		packetConn, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if listenErr != nil {
			return listenErr
		}
		defer packetConn.Close()
		remote, resolveErr := net.ResolveUDPAddr("udp4", address)
		if resolveErr != nil {
			return resolveErr
		}
		// The live baseline uses explicit CIDs. v1.4.0 can misroute some
		// zero-client-CID loopback captures; see the E2E scope notes.
		transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: 8}
		defer transport.Close()
		conn, err = transport.Dial(ctx, remote, clientTLS, config)
	} else {
		return fmt.Errorf("unknown fixture mode %q", mode)
	}
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "fixture complete")
	if protocol == "datagram" {
		for _, want := range datagramData(token) {
			if mode == "client" {
				if err := conn.SendDatagram(want); err != nil {
					return err
				}
			}
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil || !bytes.Equal(data, want) {
				return fmt.Errorf("DATAGRAM peer message mismatch: %w", err)
			}
			if mode == "server" {
				if err := conn.SendDatagram(data); err != nil {
					return err
				}
			}
		}
	} else {
		for i := byte(1); i <= 2; i++ {
			query, answer := dnsWire(token, i, true)
			if mode == "client" {
				stream, err := conn.OpenStreamSync(ctx)
				if err != nil {
					return err
				}
				if _, err := stream.Write(lengthPrefix(query)); err != nil {
					return err
				}
				if err := stream.Close(); err != nil {
					return err
				}
				data, err := io.ReadAll(io.LimitReader(stream, 65538))
				if err != nil || !bytes.Equal(data, lengthPrefix(answer)) {
					return fmt.Errorf("DoQ peer answer mismatch: %w", err)
				}
			} else {
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return err
				}
				data, err := io.ReadAll(io.LimitReader(stream, 65538))
				if err != nil || !bytes.Equal(data, lengthPrefix(query)) {
					return fmt.Errorf("DoQ peer query mismatch: %w", err)
				}
				if _, err := stream.Write(lengthPrefix(answer)); err != nil {
					return err
				}
				if err := stream.Close(); err != nil {
					return err
				}
			}
		}
	}
	if mode == "server" {
		// Keep the UDP socket until the client has received every final frame.
		select {
		case <-conn.Context().Done():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func datagramData(token string) [][]byte {
	data := append([]byte{0, 0xff}, []byte(token)...)
	return [][]byte{nil, data, data, []byte(token + "_LAST")}
}

type capturedProtocolEvent struct {
	protocol, direction, connection string
	metadata                        map[string]any
	data                            []byte
}

func readProtocolEvents(path string) ([]capturedProtocolEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []capturedProtocolEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		metadataIndex := strings.Index(line, " metadata=")
		if len(fields) < 3 || !strings.HasPrefix(line, "[") || metadataIndex < 0 || !strings.Contains(line, " encoding=hex") || strings.Contains(line, "<nil>") {
			return nil, fmt.Errorf("expected lossless typed event header")
		}
		event := capturedProtocolEvent{protocol: fields[1], direction: fields[2]}
		for _, field := range fields {
			if strings.HasPrefix(field, "connection=") {
				event.connection = strings.TrimPrefix(field, "connection=")
			}
		}
		if event.connection == "" || json.Unmarshal([]byte(line[metadataIndex+10:]), &event.metadata) != nil || !scanner.Scan() {
			return nil, fmt.Errorf("incomplete event metadata")
		}
		event.data, err = hex.DecodeString(scanner.Text())
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func verifyProtocol(path, protocol, token, phase string) error {
	events, err := readProtocolEvents(path)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no live events")
	}
	for _, event := range events {
		if event.connection != events[0].connection {
			return fmt.Errorf("unexpected connection identity change")
		}
	}
	if strings.HasPrefix(protocol, "sse") || protocol == "grpc" {
		return verifyHTTPEvents(events, protocol, token, phase)
	}
	if protocol == "smtp" || protocol == "connect" || protocol == "https-connect" {
		return verifyUpgrade(events, protocol, token)
	}
	if protocol == "websocket" {
		return verifyWebSocket(events, token)
	}
	var expected []wireStep
	switch {
	case protocol == "datagram":
		for _, data := range datagramData(token) {
			expected = append(expected, wireStep{false, data}, wireStep{true, data})
		}
	case protocol == "dot" || protocol == "doq" || strings.HasPrefix(protocol, "doh"):
		for i := byte(1); i <= 2; i++ {
			query, answer := dnsWire(token, i, protocol == "doq")
			expected = append(expected, wireStep{false, query}, wireStep{true, answer})
		}
	default:
		expected, err = wireSteps(protocol, token)
		if err != nil {
			return err
		}
	}
	if len(events) != len(expected) {
		return fmt.Errorf("%s captured %d messages, expected %d", protocol, len(events), len(expected))
	}
	used := make([]bool, len(events))
	for _, want := range expected {
		found := false
		for i, event := range events {
			if !used[i] && event.direction == eventDirection(want.server) && bytes.Equal(event.data, want.data) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s missing exact directional message", protocol)
		}
	}
	for _, event := range events {
		kind := event.metadata["kind"]
		switch {
		case protocol == "datagram":
			if event.protocol != "quic" || kind != "datagram" || event.metadata["encryption_level"] != "1rtt" ||
				event.metadata["offset"] != nil || event.metadata["end"] != nil || event.metadata["stream_id"] != nil {
				return fmt.Errorf("DATAGRAM boundaries or metadata lost")
			}
		case protocol == "dot" || protocol == "doq" || strings.HasPrefix(protocol, "doh"):
			transport := protocol
			if strings.HasPrefix(protocol, "doh") {
				transport = "doh"
				if event.metadata["http_protocol"] != "http/"+strings.TrimPrefix(protocol, "doh") && !(protocol == "doh1" && event.metadata["http_protocol"] == "http/1.1") {
					return fmt.Errorf("DoH HTTP version missing")
				}
			}
			if event.protocol != "dns" || kind != "message" || event.metadata["transport"] != transport || event.metadata["request_id"] == nil ||
				(event.direction == eventDirection(true) && event.metadata["matched"] != true) {
				return fmt.Errorf("DNS transaction metadata missing")
			}
			if protocol == "doq" && event.metadata["stream_end"] != true {
				return fmt.Errorf("DoQ FIN boundary missing")
			}
		case protocol == "mqtt":
			if event.protocol != "mqtt" || event.metadata["packet_name"] == nil || event.metadata["message_index"] == nil ||
				(event.data[0]>>4 == 3 && (kind != "publish" || event.metadata["qos"] != float64(0) || event.metadata["payload_length"] != float64(len(token)+7))) {
				return fmt.Errorf("MQTT control/publish metadata missing")
			}
		case protocol == "redis":
			if event.protocol != "redis" || kind == nil || event.metadata["resp_type"] == nil {
				return fmt.Errorf("Redis value metadata missing")
			}
			if bytes.Equal(event.data, respBulk(append([]byte{0, 0xff}, []byte(token)...))) &&
				(event.metadata["command"] != "GET" || event.metadata["request_id"] != float64(3)) {
				return fmt.Errorf("Redis pipeline response association lost")
			}
		}
	}
	if protocol == "dot" || protocol == "doq" || strings.HasPrefix(protocol, "doh") {
		for i := byte(1); i <= 2; i++ {
			query, answer := dnsWire(token, i, protocol == "doq")
			var requestID, responseID any
			for _, event := range events {
				if bytes.Equal(event.data, query) {
					requestID = event.metadata["request_id"]
				}
				if bytes.Equal(event.data, answer) {
					responseID = event.metadata["request_id"]
				}
			}
			if requestID == nil || requestID != responseID {
				return fmt.Errorf("DNS request/reply association mismatch")
			}
		}
	}
	return nil
}

func eventDirection(server bool) string {
	if server {
		return "server_to_client"
	}
	return "client_to_server"
}

func verifyUpgrade(events []capturedProtocolEvent, protocol, token string) error {
	innerDepth := float64(1)
	if protocol == "https-connect" {
		innerDepth = 2
	}
	for _, server := range []bool{false, true} {
		var negotiation, plaintext, outer []byte
		var innerEnded, outerEnded bool
		for _, event := range events {
			if event.direction != eventDirection(server) {
				continue
			}
			if event.metadata["upgrade_protocol"] != protocol {
				return fmt.Errorf("TLS upgrade identity missing")
			}
			switch event.metadata["kind"] {
			case "negotiation_chunk":
				if event.protocol != "starttls" || event.metadata["tls_depth"] != innerDepth-1 {
					return fmt.Errorf("plaintext negotiation incorrectly marked encrypted")
				}
				negotiation = append(negotiation, event.data...)
			case "stream_chunk":
				if protocol == "https-connect" && event.metadata["tls_depth"] == float64(1) {
					if outerEnded || event.protocol != "tls" || event.metadata["offset"] != float64(len(outer)) {
						return fmt.Errorf("outer TLS offset mismatch")
					}
					outer = append(outer, event.data...)
					continue
				}
				if innerEnded || event.protocol != "tls" || event.metadata["tls_depth"] != innerDepth || event.metadata["parent_tls_depth"] != innerDepth-1 || event.metadata["offset"] != float64(len(plaintext)) {
					return fmt.Errorf("TLS upgrade stream depth/offset mismatch")
				}
				plaintext = append(plaintext, event.data...)
			case "stream_end":
				if event.protocol != "tls" || len(event.data) != 0 || event.metadata["end"] != true {
					return fmt.Errorf("invalid TLS upgrade end marker")
				}
				if protocol == "https-connect" && event.metadata["tls_depth"] == float64(1) {
					if outerEnded || event.metadata["offset"] != float64(len(outer)) {
						return fmt.Errorf("outer TLS end offset mismatch")
					}
					outerEnded = true
				} else {
					if innerEnded || event.metadata["tls_depth"] != innerDepth || event.metadata["offset"] != float64(len(plaintext)) {
						return fmt.Errorf("inner TLS end offset mismatch")
					}
					innerEnded = true
				}
			default:
				return fmt.Errorf("unexpected live TLS upgrade event")
			}
		}
		var want []byte
		for _, step := range upgradePrelude(protocol) {
			if step.server == server {
				want = append(want, step.data...)
			}
		}
		label := "_CLIENT"
		if server {
			label = "_SERVER"
		}
		if !bytes.Equal(negotiation, want) || string(plaintext) != token+label {
			return fmt.Errorf("TLS negotiation or decrypted bytes incomplete")
		}
		if protocol == "https-connect" && (!bytes.HasPrefix(outer, want) || len(outer) <= len(want) || bytes.Contains(outer, []byte(token))) {
			return fmt.Errorf("outer TLS must retain CONNECT plus inner ciphertext")
		}
	}
	return nil
}

func verifyWebSocket(events []capturedProtocolEvent, token string) error {
	if len(events) != 10 {
		return fmt.Errorf("WebSocket captured %d events, expected 10", len(events))
	}
	client, server := websocketMessages(token)
	request, response := websocketUpgrade()
	expected := []wireStep{
		{false, request}, {true, response}, {false, client}, {true, server},
		{false, []byte("client-ping")}, {true, []byte("client-ping")},
		{true, []byte("server-ping")}, {false, []byte("server-ping")},
		{false, []byte{3, 232}}, {true, []byte{3, 232}},
	}
	for i, want := range expected {
		matches := 0
		for _, event := range events {
			if event.protocol != "websocket" || event.direction != eventDirection(want.server) || !bytes.Equal(event.data, want.data) {
				continue
			}
			kind := "control"
			if i < 2 {
				kind = "upgrade"
			} else if i < 4 {
				kind = "message"
				if event.metadata["compressed"] != true || event.metadata["opcode"] != float64(i-1) {
					return fmt.Errorf("WebSocket fragmented/compressed message metadata lost")
				}
			} else if i >= 8 && event.metadata["close_code"] != float64(1000) {
				return fmt.Errorf("WebSocket close code lost")
			}
			if event.metadata["kind"] != kind {
				return fmt.Errorf("WebSocket message/control kind mismatch")
			}
			matches++
		}
		if matches != 1 {
			return fmt.Errorf("WebSocket missing or duplicated directional event")
		}
	}
	return nil
}

func verifyHTTPEvents(events []capturedProtocolEvent, protocol, token, phase string) error {
	var body []byte
	counts := make(map[string]int)
	wantProtocol := "http/1.1"
	if strings.HasSuffix(protocol, "3") {
		wantProtocol = "http/3"
	} else if strings.HasSuffix(protocol, "2") || protocol == "grpc" {
		wantProtocol = "http/2"
	}
	requestMessages := 0
	for _, event := range events {
		if event.protocol != wantProtocol || event.metadata["stream_id"] == nil || event.metadata["stream_id"] != events[0].metadata["stream_id"] {
			return fmt.Errorf("HTTP version/stream identity mismatch")
		}
		if event.direction != eventDirection(true) {
			if protocol == "grpc" && event.metadata["kind"] == "grpc_message" {
				requestMessages++
				if string(event.data) != token+"_CLIENT" || event.metadata["message_index"] != float64(0) || event.metadata["compressed"] != false {
					return fmt.Errorf("gRPC request message mismatch")
				}
			}
			continue
		}
		kind, _ := event.metadata["kind"].(string)
		counts[kind]++
		switch kind {
		case "headers":
			if event.metadata["status"] != float64(200) || event.metadata["headers"] == nil {
				return fmt.Errorf("HTTP headers lost")
			}
			if protocol == "sse-gzip" && event.metadata["decoded_encoding"] != "gzip" {
				return fmt.Errorf("gzip expansion was not selected")
			}
		case "body_chunk":
			if event.metadata["offset"] != float64(len(body)) {
				return fmt.Errorf("HTTP body offset discontinuity")
			}
			body = append(body, event.data...)
		case "sse":
			index := counts[kind]
			if string(event.data) != fmt.Sprintf("%s_%d", token, index) || event.metadata["event"] != "update" ||
				event.metadata["last_event_id"] != fmt.Sprint(index) || event.metadata["retry_ms"] != float64(100) {
				return fmt.Errorf("SSE event data or metadata mismatch")
			}
		case "grpc_message":
			index := counts[kind] - 1
			want := []byte(nil)
			if index == 1 {
				want = []byte(token + "_SERVER")
			}
			if index > 1 || !bytes.Equal(event.data, want) || event.metadata["message_index"] != float64(index) || event.metadata["compressed"] != (index == 1) {
				return fmt.Errorf("gRPC empty/compressed message boundary mismatch")
			}
		case "trailers":
			if event.metadata["trailers"] == nil || (protocol == "grpc" && event.metadata["grpc_status"] != float64(0)) {
				return fmt.Errorf("HTTP/gRPC trailers lost")
			}
		case "end":
			if event.metadata["offset"] != float64(len(body)) || (protocol == "grpc" && event.metadata["grpc_status"] != float64(0)) {
				return fmt.Errorf("HTTP/gRPC completion metadata mismatch")
			}
		default:
			return fmt.Errorf("unexpected HTTP event %q", kind)
		}
	}
	if counts["headers"] != 1 || counts["body_chunk"] == 0 {
		return fmt.Errorf("HTTP headers/body not delivered live")
	}
	if protocol == "grpc" && requestMessages != 1 {
		return fmt.Errorf("gRPC request semantic event missing or duplicated")
	}
	if phase == "live" {
		if counts["end"] != 0 || counts["trailers"] != 0 || (protocol == "grpc" && counts["grpc_message"] != 2) || (protocol != "grpc" && counts["sse"] != 1) {
			return fmt.Errorf("semantic events did not arrive before response completion")
		}
		return nil
	}
	var want []byte
	if protocol == "grpc" {
		want = append(grpcFrame(nil, false), grpcFrame([]byte(token+"_SERVER"), true)...)
	} else {
		want = []byte(sseData(token, 1) + sseData(token, 2))
	}
	if !bytes.Equal(body, want) || counts["end"] != 1 || counts["trailers"] != 1 ||
		(protocol == "grpc" && counts["grpc_message"] != 2) || (protocol != "grpc" && counts["sse"] != 2) {
		return fmt.Errorf("streaming HTTP body, semantic events or completion incomplete")
	}
	return nil
}
