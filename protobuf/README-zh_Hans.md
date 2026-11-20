# 生成 Protobuf v2 消息

[English](README.md) · [协议说明](PROTOCOLS-zh_Hans.md)

运行程序仅发布 v2。协议源文件为 [proto/v2/ecaptureq.proto](proto/v2/ecaptureq.proto)，
Go 生成代码为 [gen/v2/ecaptureq.pb.go](gen/v2/ecaptureq.pb.go)。修改 schema 后在 Linux
重新生成，禁止手工修改生成代码。

当前生成文件记录 `protoc v6.32.1`、`protoc-gen-go v1.36.10`；使用这些版本保持可复现，
并将 `protoc-gen-go` 放入 `PATH`。`go.mod` 中的 Go Protobuf runtime 是独立依赖。
本协议没有 gRPC service，不需要 gRPC 生成插件。

在 Linux、仓库根目录执行：

```bash
protoc --proto_path=protobuf/proto \
  --go_out=protobuf/gen --go_opt=paths=source_relative \
  protobuf/proto/v2/ecaptureq.proto
go test -race ./protobuf/v2 ./pkg/ecaptureq
```

schema 与生成结果须一起审阅和提交。v2 内保留字段编号，删除字段应声明 reserved。
Protobuf namespace 是 `ecapture.v2`；Go 消费端导入
`pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"`。
[校验辅助包](v2/validate.go) 提供 `ValidateLogEntry`、`ValidateEvent`，以及
`ecapture.v2` WebSocket 子协议常量，导入路径为
`github.com/gojue/ecapture/v2/protobuf/v2`。

v1 文件保留为独立历史定义，不构成运行时兼容层。两个版本的 descriptor 可以共存，
但事件负载不具备 wire compatibility。接收端必须升级 v2 并协商 `ecapture.v2`，
不提供自动降级。参见 [接收端示例](../examples/ecaptureq_client/README.md)。
