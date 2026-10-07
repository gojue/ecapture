// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/gojue/ecapture/v2/internal/events"
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func BenchmarkTLSDataEventDecode(b *testing.B) {
	sample := benchmarkTLSDataSample(b)
	decoder := &tlsEventDecoder{}

	b.ReportAllocs()
	b.SetBytes(MaxDataSize)
	b.ResetTimer()
	for range b.N {
		event, err := decoder.Decode(nil, sample)
		if err != nil {
			b.Fatal(err)
		}
		if event == nil {
			b.Fatal("decoder returned a nil event")
		}
	}
}

func BenchmarkTLSDataEventTextPipeline(b *testing.B) {
	sample := benchmarkTLSDataSample(b)
	decoder := &tlsEventDecoder{}
	log := logger.New(io.Discard, false)
	dispatcher := events.NewDispatcher(log)
	writer := writers.NewIOWriterAdapter(io.Discard, "benchmark-discard")
	if err := dispatcher.Register(handlers.NewTextHandler(writer, false)); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := dispatcher.Close(); err != nil {
			b.Errorf("close dispatcher: %v", err)
		}
	})

	b.ReportAllocs()
	b.SetBytes(MaxDataSize)
	b.ResetTimer()
	for range b.N {
		event, err := decoder.Decode(nil, sample)
		if err != nil {
			b.Fatal(err)
		}
		if err := dispatcher.Dispatch(event); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkTLSDataSample(tb testing.TB) []byte {
	tb.Helper()

	event := Event{
		DataType:  DataTypeWrite,
		Timestamp: 1,
		Pid:       1000,
		Tid:       1001,
		DataLen:   MaxDataSize,
		Fd:        7,
		Version:   Tls13Version,
	}
	copy(event.Comm[:], "benchmark")
	for i := range event.Data {
		event.Data[i] = byte('a' + i%26)
	}

	var sample bytes.Buffer
	fields := []any{
		event.DataType,
		event.Timestamp,
		event.Pid,
		event.Tid,
		event.Data,
		event.DataLen,
		event.Comm,
		event.Fd,
		event.Version,
		event.BioType,
	}
	for _, field := range fields {
		if err := binary.Write(&sample, binary.LittleEndian, field); err != nil {
			tb.Fatalf("encode benchmark TLS sample: %v", err)
		}
	}
	return sample.Bytes()
}
