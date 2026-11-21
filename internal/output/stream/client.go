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

package stream

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/gojue/ecapture/v2/internal/output/pcapng"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
)

const writeTimeout = 5 * time.Second

type Client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	module         string
	heartBeatCount int64
	done           chan struct{}
	stopOnce       sync.Once
	pumps          sync.WaitGroup
	graceful       atomic.Bool
	failed         atomic.Bool
	// session belongs to Server.nativeMu, not the transport goroutines.
	session *pcapng.Session
}

func (c *Client) readPump() {
	defer c.pumps.Done()
	defer c.stop()
	for {
		var data []byte
		if err := websocket.Message.Receive(c.conn, &data); err != nil {
			return
		}
	}
}

func (c *Client) writePump() {
	defer c.pumps.Done()
	defer c.stop()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	if err := c.sendHeartbeat(); err != nil {
		return
	}
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.finish(c.graceful.Load())
				return
			}
			if err := c.sendMessage(message); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) sendMessage(message []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return websocket.Message.Send(c.conn, message)
}

func (c *Client) sendHeartbeat() error {
	entry := &pb.LogEntry{
		Module:  c.module,
		LogType: pb.LogType_LOG_TYPE_HEARTBEAT,
		Payload: &pb.LogEntry_HeartbeatPayload{HeartbeatPayload: &pb.Heartbeat{
			Message:   fmt.Sprintf("heartbeat:%d", c.heartBeatCount),
			Timestamp: time.Now().Unix(), Count: c.heartBeatCount,
		}},
	}
	data, err := proto.Marshal(entry)
	if err != nil {
		return err
	}
	if err = c.sendMessage(data); err != nil {
		return err
	}
	c.heartBeatCount++
	return nil
}

var closeFrameCodec = websocket.Codec{Marshal: func(value any) ([]byte, byte, error) {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, value.(uint16))
	return body, websocket.CloseFrame, nil
}}

func (c *Client) stop() { c.finish(false) }

func (c *Client) finish(normal bool) {
	c.stopOnce.Do(func() {
		c.hub.unregisterClient(c)
		if c.conn != nil {
			status := uint16(1011)
			if normal {
				status = 1000
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
			_ = closeFrameCodec.Send(c.conn, status)
			// Conn.Close also writes its default close frame. An expired write
			// deadline suppresses that duplicate while still closing the socket.
			_ = c.conn.SetWriteDeadline(time.Now())
			_ = c.conn.Close()
		}
		close(c.done)
	})
}
