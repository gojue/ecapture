# Generating Protobuf messages

[中文](README-zh_Hans.md) · [Wire protocol](PROTOCOLS.md)

Source: [proto/v1/ecaptureq.proto](proto/v1/ecaptureq.proto).
Generated Go messages: [gen/v1/ecaptureq.pb.go](gen/v1/ecaptureq.pb.go).
Edit the schema and regenerate; do not hand-edit generated code.

The checked-in generated header records:

```text
protoc-gen-go v1.36.10
protoc        v6.32.1
```

Use these recorded versions for reproducible regeneration. `protoc-gen-go`
must be on `PATH`; the version of the Go Protobuf runtime in `go.mod` is a
separate dependency. The schema defines messages and enums, with no gRPC
service, so `protoc-gen-go-grpc` is not needed.

On Linux, from the repository root:

```bash
protoc --proto_path=protobuf/proto \
  --go_out=protobuf/gen --go_opt=paths=source_relative \
  protobuf/proto/v1/ecaptureq.proto
```

Review the schema and generated diff together and include both in the same
change. Preserve existing field numbers and enum values for wire compatibility.
Consumers import `github.com/gojue/ecapture/v2/protobuf/gen/v1` as `pb`;
`option go_package = "./pb"` in the schema does not change that module import.
