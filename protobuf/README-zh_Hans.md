# Protobuf 编译指南

本项目使用 Protocol Buffers 来定义 ecapture 使用的消息格式。
源 `.proto` 文件位于 `protobuf/proto`，生成的 Go 代码位于 `protobuf/gen`。

## 环境依赖

在重新生成代码之前，请确认已安装以下工具：

- `protoc`（Protocol Buffers 编译器）
- `protoc-gen-go`
- `protoc-gen-go-grpc`

当前仓库中的生成文件使用如下版本的工具编译得到：

```text
protoc-gen-go v1.36.6
protoc        v6.32.1
```

建议使用 **不低于** 以上版本的 `protoc` 和 `protoc-gen-go` / `protoc-gen-go-grpc` 来重新编译，以避免兼容性问题。

## 重新生成 Go 代码

从仓库 **根目录** 执行以下命令：

```bash
protoc --proto_path=protobuf/proto \
       --go_out=protobuf/gen --go_opt=paths=source_relative \
       --go-grpc_out=protobuf/gen --go-grpc_opt=paths=source_relative \
       protobuf/proto/v1/ecaptureq.proto
```

该命令将会：

- 从 `protobuf/proto` 目录读取 `.proto` 文件
- 在 `protobuf/gen` 目录下生成对应的 Go 源码，保持与源文件相对路径一致
- 同时生成普通 Protobuf 消息和 gRPC 相关的代码（如果 `.proto` 中定义了 service）

生成完成后，请将 `protobuf/gen/v1` 下更新的文件一并提交到版本控制。