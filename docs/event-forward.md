# 社区事件转发集成

以下项目提供 GUI 或 Burp Suite 接入。这里保留发现入口，不据此声明其与当前 eCapture
协议兼容；使用前请核对目标项目支持的 eCapture 版本及消息格式。

| 项目 | 用途 | 作者 |
| --- | --- | --- |
| [eCaptureQ](https://github.com/gojue/ecaptureQ) | eCapture 的跨平台 GUI 客户端 | zenyanle |
| [eCapture Burp Bridge](https://github.com/hypernova274/eCapture-burp-bridge) | 通过 WebSocket 向 Burp Suite 转发捕获流量的桥接项目 | hypernova274 |
| [eCapture Burp](https://github.com/zitoxxx/eCaptureBurp) | 接收 eCapture TLS/HTTP 流量的 Burp Suite 扩展 | zitoxxx |

当前仓库的接入契约见[事件转发 API](event-forward-api-zh_Hans.md)和
[Protobuf 协议](../protobuf/PROTOCOLS-zh_Hans.md)。
`--output tcp://HOST:PORT` 主动发送 Protobuf v2 JSON Lines；
`--stream-listen ws://HOST:PORT/PATH` 监听二进制 Protobuf v2 订阅，客户端必须协商
`ecapture.v2`。接收端需按 `log_type` 区分运行日志和事件，再按事件格式处理
TEXT、KEYLOG 或 PCAPNG。旧参数和 v1 协议没有兼容层；GUI 或插件需完成对应适配，
不能仅替换连接地址。
