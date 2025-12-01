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
	"time"

	"github.com/gojue/ecapture/pkg/util/ws"
	pb "github.com/gojue/ecapture/protobuf/gen/v1"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

const LogBuffLen = 128

type Server struct {
	addr              string
	logbuff           [][]byte
	handler           func([]byte)
	hub               *Hub
	ws                *ws.Server
	logger            io.Writer
	ctx               context.Context
	heartbeatInterval time.Duration
}

// NewServer 创建一个新的服务器实例
func NewServer(addr string, logWriter io.Writer, heartbeatInterval int) *Server {
	s := &Server{
		addr:              addr,
		logbuff:           make([][]byte, 0, LogBuffLen),
		logger:            logWriter,
		hub:               newHub(),
		ctx:               context.Background(),
		heartbeatInterval: time.Duration(heartbeatInterval) * time.Second,
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

	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256), logger: s.logger, heartbeatInterval: s.heartbeatInterval}
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
		c.send <- log
	}
}

// WriteLog writes data to the WebSocket server.
func (s *Server) WriteLog(data []byte) (n int, e error) {
	le := new(pb.LogEntry)
	le.LogType = pb.LogType_LOG_TYPE_PROCESS_LOG
	le.Payload = &pb.LogEntry_RunLog{RunLog: string(data)}
	encodedData, err := proto.Marshal(le)
	// 如果程序初始化的日志缓冲区已满，则不再添加新的日志
	if len(s.logbuff) <= LogBuffLen {
		if err == nil {
			s.logbuff = append(s.logbuff, encodedData)
		}
		return len(data), nil
	}
	s.hub.broadcastMessage(encodedData)
	return len(data), nil
}

// WriteEvent writes an event to the WebSocket server.
func (s *Server) WriteEvent(data []byte) (n int, e error) {

	s.hub.broadcastMessage(data)
	return len(data), nil
}

func (s *Server) Close() {
	s.ctx.Done()
}
