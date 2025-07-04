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
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestServer_HandleWebSocket(t *testing.T) {
	var receivedData []byte
	var wg sync.WaitGroup
	wg.Add(1)

	// 创建服务器
	server := NewServer(":0", func(data []byte) {
		receivedData = data
		wg.Done()
	})

	// 创建测试服务器
	testServer := httptest.NewServer(websocket.Handler(server.handleWebSocket))
	defer testServer.Close()

	// 创建客户端连接
	url := "ws" + testServer.URL[4:] + "/"
	conn, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// 发送base64编码的数据
	testData := "hello world"
	encodedData := base64.StdEncoding.EncodeToString([]byte(testData))
	err = websocket.Message.Send(conn, encodedData)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// 等待数据处理
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		if string(receivedData) != testData {
			t.Errorf("Expected %s, got %s", testData, string(receivedData))
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for data processing")
	}
}

func TestServer_Start(t *testing.T) {
	server := NewServer(":0", nil)

	// 测试启动服务器（这里只验证不会panic）
	go func() {
		err := server.Start()
		if err != nil {
			t.Errorf("Failed to start server: %v", err)
		}
	}()

	// 给服务器一点时间启动
	time.Sleep(100 * time.Millisecond)
}
