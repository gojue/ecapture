// Copyright 2025 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/gojue/ecapture/v2/internal/domain"
	captureerrors "github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/pcapng"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
)

const (
	LogBuffLen = 128
	maxClients = 32
)

type Server struct {
	addr      string
	path      string
	ctx       context.Context
	cancel    context.CancelFunc
	hub       *Hub
	httpMu    sync.Mutex
	http      *http.Server
	listener  net.Listener
	nativeMu  sync.Mutex
	active    bool
	format    domain.CaptureFormat
	module    atomic.Value
	ifName    string
	filter    string
	logger    *logger.Logger
	clients   map[*Client]struct{}
	closing   bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

func NewServer(addr string, logWriter io.Writer) *Server {
	return NewServerWithPath(addr, "/", logWriter)
}

// NewServerWithPath exposes only the configured path and Protobuf v2 protocol.
func NewServerWithPath(addr, path string, logWriter io.Writer) *Server {
	if path == "" {
		path = "/"
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{addr: addr, path: path, ctx: ctx, cancel: cancel, logger: logger.New(logWriter, false), clients: make(map[*Client]struct{})}
	s.module.Store("")
	s.hub = newHub(ctx)
	return s
}

// BeginCapture starts one output generation. A subscriber's native file begins
// at connection time, with its own headers and only future packets and keys.
func (s *Server) BeginCapture(format domain.CaptureFormat, module, ifName, filter string, l *logger.Logger) error {
	switch format {
	case domain.CaptureFormatText, domain.CaptureFormatKeylog, domain.CaptureFormatPcapng:
	default:
		return fmt.Errorf("unsupported subscription capture format %q", format)
	}
	s.nativeMu.Lock()
	defer s.nativeMu.Unlock()
	if s.closing {
		return fmt.Errorf("subscription server is closed")
	}
	if s.active {
		return fmt.Errorf("subscription capture generation is already active")
	}
	s.format = format
	s.module.Store(module)
	s.ifName = ifName
	s.filter = filter
	if l != nil {
		s.logger = l
	}
	s.active = true
	return nil
}

// EndCapture closes native encoders before draining transport queues. The
// listener remains available for a later generation; clients reconnect into a
// new file instead of appending unrelated output to a previous artifact.
func (s *Server) EndCapture() error {
	s.nativeMu.Lock()
	s.active = false
	var closeErrors []error
	for client := range s.clients {
		if client.session != nil {
			err := client.session.Close()
			client.session = nil
			if err != nil {
				client.failed.Store(true)
				if !emptyCaptureOnly(err) && !errors.Is(err, errClosedSubscriber) {
					closeErrors = append(closeErrors, err)
				}
			}
		}
	}
	clients := s.hub.drainClients()
	s.nativeMu.Unlock()
	timer := time.NewTimer(writeTimeout + time.Second)
	defer timer.Stop()
	for _, client := range clients {
		if client.conn == nil {
			continue
		}
		select {
		case <-client.done:
		case <-timer.C:
			for _, pending := range clients {
				pending.stop()
			}
			return errors.Join(append(closeErrors, fmt.Errorf("subscription shutdown timed out"))...)
		}
	}
	return errors.Join(closeErrors...)
}

// AbortCapture marks an interrupted generation before draining it. Receivers
// must keep such native artifacts partial even if their final block is valid.
func (s *Server) AbortCapture() error {
	s.nativeMu.Lock()
	for client := range s.clients {
		client.failed.Store(true)
	}
	s.nativeMu.Unlock()
	return s.EndCapture()
}

// An empty late subscription is not a capture failure, but its receiver must
// not be told that it received a successful capture file.
func emptyCaptureOnly(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !emptyCaptureOnly(child) {
				return false
			}
		}
		return true
	}
	value, ok := err.(*captureerrors.Error)
	return ok && value.Code == captureerrors.ErrCodeEventNotReady && value.Cause == nil
}

func (s *Server) Start() error {
	server, listener, err := s.prepare()
	if err != nil {
		return err
	}
	return s.serve(server, listener)
}

func (s *Server) StartAsync() (<-chan error, error) {
	server, listener, err := s.prepare()
	if err != nil {
		return nil, err
	}
	result := make(chan error, 1)
	go func() { defer close(result); result <- s.serve(server, listener) }()
	return result, nil
}

func (s *Server) prepare() (*http.Server, net.Listener, error) {
	wsHandler := websocket.Server{
		Handshake: func(config *websocket.Config, r *http.Request) error {
			origin, err := websocket.Origin(config, r)
			if err != nil || origin == nil {
				return fmt.Errorf("valid WebSocket Origin is required")
			}
			config.Origin = origin
			for _, offered := range config.Protocol {
				if offered == protocol.Subprotocol {
					config.Protocol = []string{protocol.Subprotocol}
					return nil
				}
			}
			return fmt.Errorf("WebSocket subprotocol %s is required", protocol.Subprotocol)
		},
		Handler: websocket.Handler(s.handleWebSocket),
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != s.path {
			http.NotFound(w, r)
			return
		}
		s.nativeMu.Lock()
		ready := s.active && !s.closing
		s.nativeMu.Unlock()
		if !ready {
			http.Error(w, "capture generation is not active", http.StatusServiceUnavailable)
			return
		}
		wsHandler.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: s.addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	if s.http != nil {
		return nil, nil, fmt.Errorf("subscription server already started")
	}
	if s.ctx.Err() != nil {
		return nil, nil, fmt.Errorf("subscription server is closed")
	}
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for stream subscription on %s: %w", s.addr, err)
	}
	s.http = server
	s.listener = listener
	return server, listener, nil
}

func (s *Server) serve(server *http.Server, listener net.Listener) error {
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleWebSocket(conn *websocket.Conn) {
	s.nativeMu.Lock()
	if s.closing || !s.active {
		s.nativeMu.Unlock()
		_ = conn.Close()
		return
	}
	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256), module: s.module.Load().(string), done: make(chan struct{})}
	if err := s.hub.registerClient(s.ctx, client); err != nil {
		s.nativeMu.Unlock()
		client.stop()
		return
	}
	if s.format == domain.CaptureFormatPcapng {
		session, err := pcapng.NewSubscriptionSession(&clientPcapngSink{server: s, client: client}, 65535, s.ifName, s.filter, s.logger, 4<<20)
		if err != nil {
			s.nativeMu.Unlock()
			client.stop()
			return
		}
		client.session = session
	}
	s.clients[client] = struct{}{}
	s.wg.Add(1)
	client.pumps.Add(2)
	s.nativeMu.Unlock()
	defer s.wg.Done()
	go client.writePump()
	go client.readPump()
	<-client.done
	client.pumps.Wait()
	s.nativeMu.Lock()
	delete(s.clients, client)
	if client.session != nil {
		_ = client.session.Close()
		client.session = nil
	}
	s.nativeMu.Unlock()
}

func (s *Server) PublishLog(ctx context.Context, record domain.OperationalLogRecord) error {
	entry := output.LogEntryForRecord(record)
	entry.Module = s.module.Load().(string)
	module, collectorInfo := collectorInfoModule(record.Message)
	if collectorInfo {
		entry.Module = module
	}
	data, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal process log: %w", err)
	}
	return s.hub.publish(ctx, data, true, collectorInfo)
}

// Runtime information is retained independently of the bounded log ring so a
// late subscriber always receives the current generation's source metadata.
func collectorInfoModule(message string) (string, bool) {
	if len(message) > 256<<10 {
		return "", false
	}
	var record struct {
		Event         string `json:"event"`
		SchemaVersion int    `json:"schemaVersion"`
		Collector     *struct {
			Module string `json:"module"`
		} `json:"collector"`
	}
	if json.Unmarshal([]byte(message), &record) != nil || record.Event != "collector_info" || record.SchemaVersion != 1 || record.Collector == nil {
		return "", false
	}
	return record.Collector.Module, true
}

func (s *Server) PublishEvent(ctx context.Context, event domain.CapturedEventEnvelope) error {
	// The process-wide pcapng byte stream began before a late subscriber. Its
	// bytes cannot be appended to that subscriber's independently encoded file.
	if event.Format == domain.CaptureFormatPcapng {
		return nil
	}
	entry := output.LogEntryForEvent(event)
	entry.Module = s.module.Load().(string)
	if err := protocol.ValidateLogEntry(entry); err != nil {
		return err
	}
	data, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal captured event: %w", err)
	}
	return s.hub.publish(ctx, data, false, false)
}

func (s *Server) PublishPacket(ctx context.Context, packet domain.CapturedPacket) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.nativeMu.Lock()
	defer s.nativeMu.Unlock()
	if !s.active || s.format != domain.CaptureFormatPcapng {
		return nil
	}
	var failures []error
	for client := range s.clients {
		select {
		case <-client.done:
			continue
		default:
		}
		if client.session == nil || client.failed.Load() {
			continue
		}
		err := client.session.WritePacketWithProcess(packet.Data, packet.Timestamp, packet.PID, packet.ProcessName, packet.ProcessEndpoint, packet.ProcessArgs, packet.ProcessArgsTruncated)
		if err != nil && !errors.Is(err, errClosedSubscriber) {
			client.failed.Store(true)
			s.hub.unregisterClient(client)
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Server) PublishKeylog(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.nativeMu.Lock()
	defer s.nativeMu.Unlock()
	if !s.active || s.format != domain.CaptureFormatPcapng {
		return nil
	}
	var failures []error
	for client := range s.clients {
		select {
		case <-client.done:
			continue
		default:
		}
		if client.session == nil || client.failed.Load() {
			continue
		}
		err := client.session.WriteKeyLog(data)
		if err != nil && !errors.Is(err, errClosedSubscriber) {
			client.failed.Store(true)
			s.hub.unregisterClient(client)
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

type clientPcapngSink struct {
	server *Server
	client *Client
}

func (w *clientPcapngSink) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	entry := output.LogEntryForEvent(domain.CapturedEventEnvelope{Format: domain.CaptureFormatPcapng, Payload: data})
	entry.Module = w.client.module
	encoded, err := proto.Marshal(entry)
	if err == nil {
		err = w.server.hub.target(w.server.ctx, w.client, encoded)
	}
	if err != nil {
		return 0, err
	}
	return len(data), nil
}
func (w *clientPcapngSink) Name() string { return "subscriber-pcapng" }
func (w *clientPcapngSink) Flush() error { return nil }
func (w *clientPcapngSink) Close() error { return nil }

func (s *Server) Name() string            { return "stream-listen" }
func (s *Server) DroppedMessages() uint64 { return s.hub.droppedCount() }

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.nativeMu.Lock()
		s.closing = true
		s.nativeMu.Unlock()
		s.closeErr = s.EndCapture()
		s.cancel()
		s.httpMu.Lock()
		server := s.http
		s.httpMu.Unlock()
		if server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.closeErr = errors.Join(s.closeErr, server.Shutdown(ctx))
			cancel()
		}
		s.hub.wait()
		s.wg.Wait()
	})
	return s.closeErr
}

var _ domain.OperationalLogSink = (*Server)(nil)
var _ domain.CapturedEventSink = (*Server)(nil)
var _ domain.PcapngObserver = (*Server)(nil)
