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
	"bytes"
	"github.com/rs/zerolog"
	"golang.org/x/net/websocket"
	"time"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte

	logger zerolog.Logger
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.logger.Debug().Msgf("WebSocket connection info %s, origin:%s", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String())
	for {
		var data []byte
		// 检查连接状态
		if c.conn == nil {
			c.logger.Error().Msg("WebSocket connection is nil")
			break
		}
		err := websocket.Message.Receive(c.conn, &data)
		if err != nil {
			c.logger.Error().Err(err).Msg("readPump: error receiving message")
			break
		}
		c.logger.Info().Msgf("Client:%s:%s, readPump: %s", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String(), string(data))
	}
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// The hub closed the channel.
				c.logger.Error().Msg("writePump: sender channel closed")
				return
			}
			err := websocket.Message.Send(c.conn, string(message))
			if err != nil {
				c.logger.Error().Err(err).Msg("writePump: error sending message")
				return
			}
			c.logger.Debug().Msgf("Client:%s:%s, writePump: %s", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String(), string(bytes.TrimSpace(message)))
		case <-ticker.C:
			websocket.Message.Send(c.conn, newline)
		}
	}
}
