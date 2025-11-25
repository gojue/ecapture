# Protobuf Compilation Guide

This project uses Protocol Buffers to define the messages used by ecapture.
The generated Go code lives under `protobuf/gen`, and the source `.proto` files
are under `protobuf/proto`.

## Prerequisites

Make sure you have the following tools installed:

- `protoc` (Protocol Buffers compiler)
- `protoc-gen-go`
- `protoc-gen-go-grpc`

The current generated files were built with:

```text
protoc-gen-go v1.36.6
protoc        v6.32.1
```

It is recommended to use these versions or newer when regenerating the code.

## How to Re-Generate Go Code

From the **repository root directory**, run:

```bash
protoc --proto_path=protobuf/proto \
	--go_out=protobuf/gen --go_opt=paths=source_relative \
	--go-grpc_out=protobuf/gen --go-grpc_opt=paths=source_relative \
	protobuf/proto/v1/ecaptureq.proto
```

This command will:

- Read `.proto` files from `protobuf/proto`
- Generate Go files into `protobuf/gen` with paths relative to the source
- Generate both regular protobuf messages and gRPC service stubs (if any)

After regenerating, commit the updated files under `protobuf/gen/v1`.

