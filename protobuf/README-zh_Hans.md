# 生成 Protobuf 消息

[English](README.md) · [传输协议](PROTOCOLS-zh_Hans.md)

源文件：[proto/v1/ecaptureq.proto](proto/v1/ecaptureq.proto)。
生成的 Go 消息：[gen/v1/ecaptureq.pb.go](gen/v1/ecaptureq.pb.go)。
修改协议后重新生成，不要手工编辑生成代码。

当前生成文件头记录的工具版本为：

```text
protoc-gen-go v1.36.10
protoc        v6.32.1
```

使用这组已记录版本可保持生成结果可复现。`protoc-gen-go` 必须位于 `PATH`；
`go.mod` 中的 Go Protobuf 运行库版本是独立依赖。
当前协议只有消息和枚举，没有 gRPC service，无需 `protoc-gen-go-grpc`。

在 Linux 上，从仓库根目录执行：

```bash
protoc --proto_path=protobuf/proto \
  --go_out=protobuf/gen --go_opt=paths=source_relative \
  protobuf/proto/v1/ecaptureq.proto
```

一起审查源协议和生成代码的差异，并将两者纳入同一变更。
保留既有字段编号和枚举值，维护传输兼容性。
消费者以 `pb` 别名导入 `github.com/gojue/ecapture/v2/protobuf/gen/v1`；
协议中的 `option go_package = "./pb"` 不会改变此模块导入路径。
