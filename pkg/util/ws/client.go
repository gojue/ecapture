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
	"golang.org/x/net/websocket"
)

func NewClient() *Client {
	return &Client{}
}

type Client struct {
	conn *websocket.Conn
}

// Write 实现 io.Writer 接口
func (w *Client) Write(p []byte) (n int, err error) {
	// 使用base64编码器
	err = websocket.Message.Send(w.conn, base64.StdEncoding.EncodeToString(p))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *Client) Dial(url, protocol, origin string) error {
	var err error
	w.conn, err = websocket.Dial(url, protocol, origin)
	if err != nil {
		return err
	}
	return nil

}

// Close 关闭 WebSocket 连接
func (w *Client) Close() error {
	return w.conn.Close()
}
