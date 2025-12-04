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
	"fmt"
	"io"
	"time"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
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

	logger io.Writer

	heartBeatCount int

	hbTimer *time.Ticker
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		_ = c.conn.Close()
	}()
	_, _ = c.logger.Write([]byte("readPump: starting to read messages from WebSocket connection\n"))
	for {
		var data []byte
		// 检查连接状态
		if c.conn == nil {
			_, _ = c.logger.Write([]byte("readPump: WebSocket connection is nil\n"))
			break
		}
		err := websocket.Message.Receive(c.conn, &data)
		if err != nil {
			_, _ = c.logger.Write([]byte("readPump: error receiving message\n"))
			break
		}
		//_, _ = c.logger.Write([]byte(fmt.Sprintf("Client:%s:%s, readPump: %s\n", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String(), string(data))))
	}
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	c.hbTimer = time.NewTicker(15 * time.Second)
	defer func() {
		c.hbTimer.Stop()
		_ = c.conn.Close()
	}()

	// heartbeat when client connected
	err := c.Heartbeat()
	if err != nil {
		_, _ = c.logger.Write([]byte(fmt.Sprintf("writePump: error sending heartbeat: %v\n", err)))
	}

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// The hub closed the channel.
				_, _ = c.logger.Write([]byte("writePump: sender channel closed\n"))
				return
			}
			err := websocket.Message.Send(c.conn, message)
			if err != nil {
				_, _ = c.logger.Write([]byte("writePump: error sending message\n"))
				return
			}
			//_, _ = c.logger.Write([]byte(fmt.Sprintf("Client:%s:%s, writePump: %s\n", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String(), string(bytes.TrimSpace(message)))))
		case <-c.hbTimer.C:
			err := c.Heartbeat()
			if err != nil {
				_, _ = c.logger.Write([]byte(fmt.Sprintf("writePump: error sending heartbeat: %v\n", err)))
			}
		}

	}
}

func (c *Client) Heartbeat() error {
	hb := new(pb.Heartbeat)
	hb.Message = fmt.Sprintf("heartbeat:%d", c.heartBeatCount)
	hb.Timestamp = time.Now().Unix()
	hb.Count = int64(c.heartBeatCount)

	le := new(pb.LogEntry)
	le.LogType = pb.LogType_LOG_TYPE_HEARTBEAT
	le.Payload = &pb.LogEntry_HeartbeatPayload{HeartbeatPayload: hb}
	encodedData, err := proto.Marshal(le)
	if err != nil {
		return err
	}
	c.send <- encodedData
	c.heartBeatCount++
	return err
}
