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
	"github.com/gojue/ecapture/pkg/util/ws"
	"github.com/rs/zerolog"
	"golang.org/x/net/websocket"
	"time"
)

const LogBuffLen = 128

type Server struct {
	addr    string
	logbuff []string
	handler func([]byte)
	hub     *Hub
	ws      *ws.Server
	logger  zerolog.Logger
	ctx     context.Context
}

// NewServer 创建一个新的服务器实例
func NewServer(addr string, logger zerolog.Logger) *Server {
	s := &Server{
		addr:    addr,
		logbuff: make([]string, 0, LogBuffLen),
		logger:  logger,
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
	// 启动心跳广播goroutine ，测试用
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		var i = 0
		defer ticker.Stop()
		for range ticker.C {
			s.logger.Debug().Msg("heartbeat tick")
			s.Write([]byte(fmt.Sprintf("heartbeat: %d", i)))
			i++
		}
	}()

	err := s.ws.Start()
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) handleWebSocket(conn *websocket.Conn) {
	s.logger.Info().Msgf("New WebSocket connection from %s", conn.RemoteAddr())
	defer func() {
		s.logger.Info().Msgf("WebSocket connection closed from %s", conn.RemoteAddr())
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

func (s *Server) Write(data []byte) (int, error) {
	if s.ws == nil {
		return 0, fmt.Errorf("websocket server not initialized")
	}
	if s.hub == nil {
		return 0, fmt.Errorf("hub not initialized")
	}
	s.hub.broadcastMessage(data)
	return len(data), nil
}

func (s *Server) WriteLog(data []byte) {
	if len(s.logbuff) >= LogBuffLen {
		return
	}
	s.logbuff = append(s.logbuff, string(data))
	s.Write(data)
}

func (s *Server) Close() {
	s.ctx.Done()
	s.logger.Info().Msg("Server closed")
}
