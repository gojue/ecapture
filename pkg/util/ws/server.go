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
	addr            string
	handleWebSocket func(*websocket.Conn)
}

// NewServer 创建一个新的WebSocket服务器实例
func NewServer(addr string, handler func(conn *websocket.Conn)) *Server {
	return &Server{
		addr:            addr,
		handleWebSocket: handler,
	}
}

func (s *Server) Start() error {
	if s.handleWebSocket == nil {
		return fmt.Errorf("handleWebSocket function is not set")
	}

	mux := http.NewServeMux()
	mux.Handle("/", websocket.Handler(s.handleWebSocket))
	return http.ListenAndServe(s.addr, mux)
}
