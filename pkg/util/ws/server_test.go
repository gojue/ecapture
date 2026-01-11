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
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestServer_HandleWebSocket(t *testing.T) {
	var receivedData string
	var wg sync.WaitGroup
	wg.Add(1)

	wsUrl := "ws://127.0.0.1:28257"
	// 创建服务器
	server := NewServer("127.0.0.1:28257", wsHandler)
	go func() {
		err := server.Start()
		if err != nil {
			t.Errorf("Failed to start server: %v", err)
			return
		}
	}()

	time.Sleep(1 * time.Second) // 等待服务器启动

	// 创建测试服务器
	testServer := httptest.NewServer(websocket.Handler(server.handleWebSocket))
	defer testServer.Close()

	// 创建客户端连接
	url := wsUrl
	fmt.Println("Connecting to WebSocket at:", url)
	conn, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
		return
	}
	defer func() {
		_ = conn.Close()
	}()

	// 发送base64编码的数据
	err = websocket.Message.Send(conn, "ping")
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
		return
	}

	go func() {
		err = websocket.Message.Receive(conn, &receivedData)
		if err != nil {
			t.Error("Failed to receive message:", err)
		}
		t.Logf("Received data: %s", receivedData)
		wg.Done()
	}()

	// 等待数据处理
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		if receivedData != "pong" {
			t.Errorf("Expected %s, got %s", "pong", receivedData)
			return
		}
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for data processing")
	}
}

func TestServer_Start(t *testing.T) {
	server := NewServer(":0", wsHandler)

	// 测试启动服务器（这里只验证不会panic）
	go func() {
		err := server.Start()
		if err != nil {
			t.Errorf("Failed to start server: %v", err)
			return
		}
	}()

	// 给服务器一点时间启动
	time.Sleep(100 * time.Millisecond)
}

func wsHandler(conn *websocket.Conn) {
	ctx := context.Background()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				_ = conn.Close()
			}
		}()

		for {
			var msg string
			if err := websocket.Message.Receive(conn, &msg); err != nil {
				return
			}
			if msg == "ping" {
				if err := websocket.Message.Send(conn, "pong"); err != nil {
					fmt.Println(err)
					return
				}
			} else {
				fmt.Println("Received message:", msg)
			}
		}
	}()

	<-ctx.Done()
}
