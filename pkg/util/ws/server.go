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
	"encoding/base64"
	"fmt"
	"golang.org/x/net/websocket"
	"net/http"
)

// Server 是一个简单的WebSocket服务器，接收base64编码的消息并调用处理函数
type Server struct {
	addr    string
	handler func([]byte)
}

/*
	server := NewServer(":8080", func(data []byte) {
	    fmt.Printf("Received: %s\n", string(data))
	})

server.Start()
*/

// NewServer 创建一个新的WebSocket服务器实例
func NewServer(addr string, handler func([]byte)) *Server {
	return &Server{
		addr:    addr,
		handler: handler,
	}
}

func (s *Server) Start() error {
	http.Handle("/", websocket.Handler(s.handleWebSocket))
	return http.ListenAndServe(s.addr, nil)
}

func (s *Server) handleWebSocket(ws *websocket.Conn) {
	defer ws.Close()

	for {
		var message string
		err := websocket.Message.Receive(ws, &message)
		if err != nil {
			fmt.Printf("WebSocket receive error: %v\n", err)
			break
		}

		// 解码base64消息
		data, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			fmt.Printf("Base64 decode error: %v\n", err)
			continue
		}

		// 调用处理函数
		if s.handler != nil {
			s.handler(data)
		}
	}
}
