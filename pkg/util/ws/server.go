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

package ws

import (
	"fmt"
	"net/http"

	"golang.org/x/net/websocket"
)

// Server 是一个简单的WebSocket服务器，接收base64编码的消息并调用处理函数
type Server struct {
	addr        string
	readHandler func([]byte)
	writeChan   chan []byte
}

const WriteChanLength = 1024 * 4

/*
	server := NewServer(":8080", func(data []byte) {
	    fmt.Printf("Received: %s\n", string(data))
	})

server.Start()
*/

// NewServer 创建一个新的WebSocket服务器实例
func NewServer(addr string, handler func([]byte)) *Server {
	return &Server{
		addr:        addr,
		readHandler: handler,
		writeChan:   make(chan []byte, WriteChanLength),
	}
}

func (s *Server) Start() error {
	http.Handle("/", websocket.Handler(s.handleWebSocket))
	return http.ListenAndServe(s.addr, nil)
}

// Write 向WebSocket连接发送数据
func (s *Server) Write(data []byte) error {
	if data == nil {
		return nil // 如果数据为nil，直接返回
	}

	select {
	case s.writeChan <- data:
		return nil // 成功写入数据到通道
	default:
		return fmt.Errorf("write channel is full") // 如果通道已满，返回错误
	}
}

// handleWebSocket 处理WebSocket连接
func (s *Server) handleWebSocket(ws *websocket.Conn) {
	defer func() {
		_ = ws.Close()
	}()

	go func() {
		for {
			var data []byte
			err := websocket.Message.Receive(ws, &data)
			if err != nil {
				fmt.Printf("WebSocket receive error: %v\n", err)
				break
			}

			// 调用处理函数
			if s.readHandler != nil {
				s.readHandler(data)
			}
		}
	}()

	go func() {
		for range s.writeChan {
			// 从写入通道中读取数据
			data := <-s.writeChan
			if data == nil {
				continue // 如果数据为nil，跳过
			}

			// 发送数据到WebSocket连接
			err := websocket.Message.Send(ws, data)
			if err != nil {
				fmt.Printf("WebSocket write error: %v\n", err)
				break
			}
		}
	}()
}
