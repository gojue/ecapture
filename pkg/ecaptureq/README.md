## eCapture WebSocket API 文档

适用于 eCapture 的 WebSocket 接口，允许客户端连接到 eCapture 服务端以接收实时事件和日志。

### 连接方式

- **协议**：WebSocket
- **地址**：`ws://<server_host>:<server_port>`

> 取决于 eCapture 的启动参数，比如：`sudo /usr/bin/ecapture tls --ecaptureq ws://192.168.71.123:28257`

### 消息格式

所有消息均为 JSON 格式，结构如下：

#### eqMessage

```json
{
  "log_type": 0,
  // 消息类型，见下方说明
  "payload": {
    ...
  }
  // 具体内容，类型依赖于 log_type
}
```

#### 消息类型

| log_type              | 说明      | payload结构        |
|-----------------------|---------|------------------|
| 0 (LogTypeHeartBeat)  | 心跳包     | HeartbeatMessage |
| 1 (LogTypeProcessLog) | 程序运行日志  | 任意字符串/日志内容       |
| 2 (LogTypeEvent)      | 捕获的事件详情 | 任意事件内容           |

##### 心跳包

心跳包的`log_type` 为 0，表示心跳包，结构如下：

```json
{
  "log_type": 0,
  "payload": {
    "timestamp": 1754144361,
    "count": 0,
    "message": "heartbeat:0"
  }
}
```

##### 程序运行日志

当服务端发送程序运行日志时，`log_type` 为 1，`payload` 为任意字符串或日志内容。

当客户端连接上服务端后，会收到服务端（即eCapture）发送的程序运行日志，比如：

```shell
2025-08-02T14:16:10Z INF AppName="eCapture(旁观者)"
2025-08-02T14:16:10Z INF HomePage=https://ecapture.cc
2025-08-02T14:16:10Z INF Repository=https://github.com/gojue/ecapture
2025-08-02T14:16:10Z INF Author="CFC4N <cfc4ncs@gmail.com>"
2025-08-02T14:16:10Z INF Description="Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64."
2025-08-02T14:16:10Z INF Version=linux_arm64:v1.3.1-20250629-b395562:5.15.0-143-generic
2025-08-02T14:16:10Z INF Listen=localhost:28256
2025-08-02T14:16:10Z INF Listen for eCaptureQ=ws://172.16.71.129:9999
```

> 即使eCapture先启动，客户端连接后也会收到这些日志。 是因为eCapture在启动时会缓存前100条日志，连接后会将这些日志发送给客户端。

你将会收到类似下面的消息：

```json
{
  "log_type": 1,
  "payload": {
    "level": "info",
    "AppName": "eCapture(旁观者)",
    "time": "2025-08-02T14:16:10Z"
  }
}
```

##### 捕获的事件详情

当服务端捕获到 hook 事件时，会以 `log_type: 2` 的消息推送事件详情，`payload` 为事件内容。

你会收到类似下面的消息：

```json
{
  "log_type": 2,
  "payload": {
    "timestamp": 0,
    "uuid": "123557_123557_curl_5_1_172.16.71.129:54870-180.101.49.44:443",
    "src_ip": "",
    "src_port": 0,
    "dst_ip": "",
    "dst_port": 0,
    "pid": 0,
    "pname": "",
    "type": 1,
    "length": 104,
    "payload_base64": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IHd3dy5iYWlkdS5jb20NCkFjY2VwdDogKi8qDQpVc2VyLUFnZW50OiBjdXJsLzcuODEuMA0KDQo="
  }
}
```

---

## Client 实现示例（Go 语言）

下面是一个简单的 Go 客户端，连接 WebSocket Server 并读取事件：

```go
package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/websocket"
)

type eqMessageType uint8

const (
	LogTypeHeartBeat  eqMessageType = 0
	LogTypeProcessLog eqMessageType = 1
	LogTypeEvent      eqMessageType = 2
)

type eqMessage struct {
	LogType eqMessageType   `json:"log_type"`
	Payload json.RawMessage `json:"payload"`
}

type HeartbeatMessage struct {
	Timestamp int64  `json:"timestamp"`
	Count     int32  `json:"count"`
	Message   string `json:"message"`
}

func main() {
	wsURL := "ws://127.0.0.1:28257" // 替换为实际地址
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		panic(err)
	}
	defer ws.Close()

	for {
		var msgData []byte
		if err := websocket.Message.Receive(ws, &msgData); err != nil {
			fmt.Println("连接断开:", err)
			break
		}

		var msg eqMessage
		if err := json.Unmarshal(msgData, &msg); err != nil {
			fmt.Println("消息解析失败:", err)
			continue
		}

		switch msg.LogType {
		case LogTypeHeartBeat:
			var hb HeartbeatMessage
			if err := json.Unmarshal(msg.Payload, &hb); err == nil {
				fmt.Printf("收到心跳: %+v\n", hb)
			}
		case LogTypeProcessLog:
			fmt.Printf("收到日志: %s\n", string(msg.Payload))
		case LogTypeEvent:
			fmt.Printf("收到事件: %s\n", string(msg.Payload))
		default:
			fmt.Printf("未知类型: %d, 内容: %s\n", msg.LogType, string(msg.Payload))
		}
	}
}
```

---

## 说明

1. 客户端通过 WebSocket 连接到服务端，持续读取消息。
2. 根据 `log_type` 字段判断消息类型，分别处理心跳、日志和事件。
3. 事件详情通过 `log_type: 2` 推送，`payload` 为事件内容， 里面有个`payload_base64`字段，表示事件的 Base64
   编码内容，需要解码后才能查看具体内容。