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
	"net/http/httptest"
	"testing"
)

func TestClient_Write(t *testing.T) {
	// 创建测试服务器
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		var message string
		err := websocket.Message.Receive(ws, &message)
		if err != nil {
			t.Errorf("Failed to receive message: %v", err)
			return
		}

		// 验证收到的是base64编码的数据
		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			t.Errorf("Failed to decode base64: %v", err)
			return
		}

		expected := "test data"
		if string(decoded) != expected {
			t.Errorf("Expected %s, got %s", expected, string(decoded))
		}
	}))
	defer server.Close()

	// 创建客户端并连接
	client := NewClient()
	url := "ws" + server.URL[4:] + "/"
	err := client.Dial(url, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// 测试Write方法
	testData := []byte("test data")
	n, err := client.Write(testData)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}
}

func TestClient_Dial(t *testing.T) {
	client := NewClient()

	// 测试连接到无效地址
	err := client.Dial("ws://invalid:99999/", "", "")
	if err == nil {
		t.Error("Expected error when dialing invalid address")
	}
}
