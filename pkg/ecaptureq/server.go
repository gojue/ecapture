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

package ecaptureq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gojue/ecapture/v2/internal/domain"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

const LogBuffLen = 128

type Server struct {
	addr      string
	logger    io.Writer
	ctx       context.Context
	cancel    context.CancelFunc
	hub       *Hub
	httpMu    sync.Mutex
	http      *http.Server
	listener  net.Listener
	clientsMu sync.Mutex
	closing   bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

func NewServer(addr string, logWriter io.Writer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{addr: addr, logger: logWriter, ctx: ctx, cancel: cancel}
	server.hub = newHub(ctx)
	return server
}

// Start serves the protobuf WebSocket endpoint until Close is called.
func (s *Server) Start() error {
	httpServer, listener, err := s.prepare()
	if err != nil {
		return err
	}
	return s.serve(httpServer, listener)
}

// StartAsync binds the listen address before returning so callers can report
// address errors synchronously and monitor later serving failures.
func (s *Server) StartAsync() (<-chan error, error) {
	httpServer, listener, err := s.prepare()
	if err != nil {
		return nil, err
	}
	result := make(chan error, 1)
	go func() {
		defer close(result)
		result <- s.serve(httpServer, listener)
	}()
	return result, nil
}

func (s *Server) prepare() (*http.Server, net.Listener, error) {
	mux := http.NewServeMux()
	mux.Handle("/", websocket.Handler(s.handleWebSocket))
	httpServer := &http.Server{Addr: s.addr, Handler: mux}
	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	if s.http != nil {
		return nil, nil, fmt.Errorf("ecaptureq server already started")
	}
	if s.ctx.Err() != nil {
		return nil, nil, fmt.Errorf("ecaptureq server is closed")
	}
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for ecaptureq on %s: %w", s.addr, err)
	}
	s.http = httpServer
	s.listener = listener
	return httpServer, listener, nil
}

func (s *Server) serve(httpServer *http.Server, listener net.Listener) error {
	err := httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleWebSocket(conn *websocket.Conn) {
	s.clientsMu.Lock()
	if s.closing {
		s.clientsMu.Unlock()
		_ = conn.Close()
		return
	}
	s.wg.Add(1)
	s.clientsMu.Unlock()
	defer s.wg.Done()
	client := &Client{
		hub:    s.hub,
		conn:   conn,
		send:   make(chan []byte, 256),
		logger: s.logger,
		done:   make(chan struct{}),
	}
	if err := s.hub.registerClient(s.ctx, client); err != nil {
		client.logf("ecaptureq client registration failed: %v", err)
		_ = conn.Close()
		return
	}
	go client.writePump()
	go client.readPump()
	select {
	case <-client.done:
	case <-s.ctx.Done():
		client.stop()
		<-client.done
	}
}

func (s *Server) PublishLog(ctx context.Context, record domain.OperationalLogRecord) error {
	entry := &pb.LogEntry{
		LogType: pb.LogType_LOG_TYPE_PROCESS_LOG,
		Payload: &pb.LogEntry_RunLog{RunLog: record.Message},
	}
	data, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal process log: %w", err)
	}
	return s.hub.publish(ctx, data, true)
}

func (s *Server) PublishEvent(ctx context.Context, event domain.CapturedEventEnvelope) error {
	entry := &pb.LogEntry{
		LogType: pb.LogType_LOG_TYPE_EVENT,
		Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{
			Timestamp:      event.Timestamp.Unix(),
			Uuid:           event.UUID,
			SrcIp:          event.SourceIP,
			SrcPort:        event.SourcePort,
			DstIp:          event.DestinationIP,
			DstPort:        event.DestinationPort,
			Pid:            int64(event.PID),
			Pname:          event.ProcessName,
			Type:           uint32(event.EventType),
			Length:         uint32(len(event.Payload)),
			Payload:        append([]byte(nil), event.Payload...),
			CaptureFormat:  captureFormat(event.Format),
			Sensitivity:    sensitivity(event.Sensitivity),
			Direction:      event.Direction,
			OriginalLength: event.OriginalLength,
			StreamId:       event.StreamID,
			Sequence:       event.Sequence,
		}},
	}
	data, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal captured event: %w", err)
	}
	return s.hub.publish(ctx, data, false)
}

func captureFormat(format domain.CaptureFormat) pb.CaptureFormat {
	switch format {
	case domain.CaptureFormatText:
		return pb.CaptureFormat_CAPTURE_FORMAT_TEXT
	case domain.CaptureFormatKeylog:
		return pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG
	case domain.CaptureFormatPcapng:
		return pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG
	default:
		return pb.CaptureFormat_CAPTURE_FORMAT_UNSPECIFIED
	}
}

func sensitivity(value domain.Sensitivity) pb.Sensitivity {
	if value == domain.SensitivitySensitive {
		return pb.Sensitivity_SENSITIVITY_SENSITIVE
	}
	return pb.Sensitivity_SENSITIVITY_NORMAL
}

func (s *Server) Name() string { return "ecaptureq" }

func (s *Server) DroppedMessages() uint64 { return s.hub.droppedCount() }

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.clientsMu.Lock()
		s.closing = true
		s.clientsMu.Unlock()
		s.cancel()
		s.httpMu.Lock()
		httpServer := s.http
		s.httpMu.Unlock()
		if httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.closeErr = httpServer.Shutdown(ctx)
			cancel()
		}
		s.hub.wait()
		s.wg.Wait()
	})
	return s.closeErr
}

var _ domain.OperationalLogSink = (*Server)(nil)
var _ domain.CapturedEventSink = (*Server)(nil)
