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
	"sync"
	"time"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

type Client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	logger         io.Writer
	heartBeatCount int64
	done           chan struct{}
	stopOnce       sync.Once
}

func (c *Client) readPump() {
	defer c.stop()
	for {
		var data []byte
		if err := websocket.Message.Receive(c.conn, &data); err != nil {
			return
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer c.stop()
	if err := c.sendHeartbeat(); err != nil {
		c.logf("writePump: error sending heartbeat: %v", err)
		return
	}
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				return
			}
			if err := websocket.Message.Send(c.conn, message); err != nil {
				c.logf("writePump: error sending message: %v", err)
				return
			}
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				c.logf("writePump: error sending heartbeat: %v", err)
				return
			}
		case <-c.hub.ctx.Done():
			return
		}
	}
}

func (c *Client) sendHeartbeat() error {
	heartbeat := &pb.Heartbeat{
		Message:   fmt.Sprintf("heartbeat:%d", c.heartBeatCount),
		Timestamp: time.Now().Unix(),
		Count:     c.heartBeatCount,
	}
	entry := &pb.LogEntry{
		LogType: pb.LogType_LOG_TYPE_HEARTBEAT,
		Payload: &pb.LogEntry_HeartbeatPayload{HeartbeatPayload: heartbeat},
	}
	data, err := proto.Marshal(entry)
	if err != nil {
		return err
	}
	if err := websocket.Message.Send(c.conn, data); err != nil {
		return err
	}
	c.heartBeatCount++
	return nil
}

func (c *Client) stop() {
	c.stopOnce.Do(func() {
		c.hub.unregisterClient(c)
		_ = c.conn.Close()
		close(c.done)
	})
}

func (c *Client) logf(format string, args ...any) {
	if c.logger == nil {
		return
	}
	_, _ = fmt.Fprintf(c.logger, format+"\n", args...)
}
