# Generating Protobuf v2 messages

[中文](README-zh_Hans.md) · [Wire protocol](PROTOCOLS.md)

The running application publishes v2 only. Source:
[proto/v2/ecaptureq.proto](proto/v2/ecaptureq.proto); generated Go types:
[gen/v2/ecaptureq.pb.go](gen/v2/ecaptureq.pb.go). Edit the schema and regenerate
on Linux; never hand-edit generated code.

The checked-in generated header records `protoc v6.32.1` and
`protoc-gen-go v1.36.10`. Use those versions for reproducible generation;
`protoc-gen-go` must be on `PATH`. The Go Protobuf runtime in `go.mod` is a
separate dependency. There are no gRPC services or gRPC generator requirements.

From the repository root on Linux:

```bash
protoc --proto_path=protobuf/proto \
  --go_out=protobuf/gen --go_opt=paths=source_relative \
  protobuf/proto/v2/ecaptureq.proto
go test -race ./protobuf/v2 ./pkg/ecaptureq
```

Review and commit schema and generated changes together. Preserve field numbers
within v2; reserve removed fields. The Protobuf namespace is `ecapture.v2` and
Go consumers import `pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"`.
[protobuf/v2](v2/validate.go) (Go import suffix `/protobuf/v2`) provides
`ValidateLogEntry`, `ValidateEvent`, and the `ecapture.v2` WebSocket subprotocol
constant.

V1 sources remain separate historical definitions, not a runtime compatibility
layer. V1 and v2 descriptors can coexist, but their event payloads are not wire
compatible. Upgrade receivers to v2 and negotiate `ecapture.v2`; there is no
automatic fallback. See the [receiver example](../examples/ecaptureq_client/README.md).
