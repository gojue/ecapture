# eCapture Protobuf Debugger

调试器使用 `ecapture.v2` WebSocket 子协议并校验 v2 `LogEntry`。
采集器通过 `--stream-listen` 开启订阅，旧 `--ecaptureq` 参数不再支持。
TEXT 事件显示元数据和正文；KEYLOG 与 PCAPNG 事件仅显示字节数摘要，其内容是
原生输出流片段，不能当作单个文本包。保存原生文件请使用
[接收端示例](../../examples/ecaptureq_client/README.md)。编译和执行需要 Linux。

eCapture WebSocket 消息的可视化调试工具，支持解析 Event、Heartbeat 和 Log 类型的 Protobuf 消息。

## 编译

```bash
go build -o pb_debugger pb_debugger.go
```

## 使用说明

### 常用命令

```bash
# 连接默认地址 (ws://127.0.0.1:28257)
./pb_debugger

# 指定服务器地址
./pb_debugger -url ws://192.168.1.100:28257

# 紧凑模式（单行显示，适合高频数据）
./pb_debugger -compact

# 十六进制模式（查看原始 Payload）
./pb_debugger -hex

# 将输出保存到文件（自动禁用颜色）
./pb_debugger -no-color > capture.log
```

### 参数列表

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-url` | `ws://127.0.0.1:28257` | WebSocket 服务器地址 |
| `-compact` | `false` | 启用单行紧凑输出模式 |
| `-hex` | `false` | 以 Hex 格式显示 Payload |
| `-max-payload` | `1024` | 限制 Payload 显示的最大字节数 |
| `-no-color` | `false` | 禁用终端彩色输出 |