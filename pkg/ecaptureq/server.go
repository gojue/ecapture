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
	"fmt"
	"io"

	"github.com/gojue/ecapture/pkg/util/ws"
	"golang.org/x/net/websocket"
)

const LogBuffLen = 128

type Server struct {
	addr    string
	logbuff []string
	handler func([]byte)
	hub     *Hub
	ws      *ws.Server
	logger  io.Writer
	ctx     context.Context
}

// NewServer 创建一个新的服务器实例
func NewServer(addr string, logWriter io.Writer) *Server {
	s := &Server{
		addr:    addr,
		logbuff: make([]string, 0, LogBuffLen),
		logger:  logWriter,
		hub:     newHub(),
		ctx:     context.Background(),
	}
	server := ws.NewServer(s.addr, s.handleWebSocket)
	s.ws = server
	go func() {
		s.hub.run()
	}()

	return s
}

// Start 启动服务器
func (s *Server) Start() error {
	err := s.ws.Start()
	return err
}

func (s *Server) handleWebSocket(conn *websocket.Conn) {
	_, _ = s.logger.Write([]byte(fmt.Sprintf("New WebSocket connection from %s", conn.RemoteAddr())))
	defer func() {
		_, _ = s.logger.Write([]byte(fmt.Sprintf("Closing WebSocket connection from %s", conn.RemoteAddr())))
	}()

	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256), logger: s.logger}
	client.hub.register <- client

	// 为新连接的客户端发送预存储的日志数据
	s.sendLogBuff(client)

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
	<-s.ctx.Done()
}

func (s *Server) sendLogBuff(c *Client) {
	for _, log := range s.logbuff {
		c.send <- []byte(log)
	}
}

func (s *Server) write(data []byte, logType eqMessageType) (int, error) {
	if s.ws == nil {
		return 0, fmt.Errorf("websocket server not initialized")
	}
	if s.hub == nil {
		return 0, fmt.Errorf("hub not initialized")
	}

	hb := new(eqMessage)
	hb.LogType = logType
	hb.Payload = data
	payload, err := hb.Encode()
	if err != nil {
		return 0, err
	}

	s.hub.broadcastMessage(payload)
	return len(data), nil
}

// WriteLog writes data to the WebSocket server.
func (s *Server) WriteLog(data []byte) (n int, e error) {
	// 如果程序初始化的日志缓冲区已满，则不再添加新的日志
	if len(s.logbuff) <= LogBuffLen {
		hb := new(eqMessage)
		hb.LogType = LogTypeProcessLog
		hb.Payload = data
		payload, err := hb.Encode()
		if err == nil {
			s.logbuff = append(s.logbuff, string(payload))
		}
	}
	return s.write(data, LogTypeProcessLog)
}

// WriteEvent writes an event to the WebSocket server.
func (s *Server) WriteEvent(data []byte) (n int, e error) {
	return s.write(data, LogTypeEvent)
}

func (s *Server) Close() {
	s.ctx.Done()
}
