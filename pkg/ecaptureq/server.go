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
	"github.com/gojue/ecapture/pkg/util/ws"
	"github.com/rs/zerolog"
)

const LogBuffLen = 100

type Server struct {
	addr    string
	logbuff []string
	handler func([]byte)
	ws      *ws.Server
	logger  *zerolog.Logger
}

// NewServer 创建一个新的服务器实例
func NewServer(addr string, logger *zerolog.Logger) *Server {
	return &Server{
		addr:    addr,
		logbuff: make([]string, 0, LogBuffLen),
		logger:  logger,
	}
}

// Start 启动服务器
func (s *Server) Start() error {
	server := ws.NewServer(s.addr, s.handler)
	s.ws = server
	err := s.ws.Start()
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) Write(data []byte) error {
	pd := new(PacketData)
	err := pd.Decode(data)
	if err != nil {
		return err
	}
	err = s.ws.Write(data)
	return err
}

func (s *Server) Read(data []byte) error {
	pd := new(PacketData)
	err := pd.Decode(data)
	if err != nil {
		return err
	}
	s.logger.Info().Msg(string(data))
	return nil
}
