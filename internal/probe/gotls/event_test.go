// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gotls

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture/internal/domain"
)

// buildEventBytes constructs a raw eBPF byte payload for GoTLSDataEvent.
// Offsets match the C struct go_tls_event exactly.
func buildEventBytes(t *testing.T,
	timestamp uint64, seq uint64, emitCPU uint32, pid, tid uint32, dataLen int32, eventType uint8,
	fd uint32, srcIP [16]byte, srcPort uint16, dstIP [16]byte, dstPort uint16,
	ipVersion uint8, comm [16]byte, payload []byte,
) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	write := func(v any) {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			t.Fatalf("binary.Write failed: %v", err)
		}
	}
	write(timestamp) // offset 0,  u64 ts_ns
	write(seq)       // offset 8,  u64 seq
	write(emitCPU)   // offset 16, u32 emit_cpu
	write(pid)       // offset 20, u32
	write(tid)       // offset 24, u32
	write(dataLen)   // offset 28, s32
	write(eventType) // offset 32, u8
	write([3]byte{}) // offset 33, pad[3]
	write(fd)        // offset 36, u32
	write(srcIP)     // offset 40, u8[16]
	write(srcPort)   // offset 56, u16
	write([2]byte{}) // offset 58, pad2
	write(dstIP)     // offset 60, u8[16]
	write(dstPort)   // offset 76, u16
	write(ipVersion) // offset 78, u8
	write(uint8(0))  // offset 79, pad3
	write(comm)      // offset 80, char[16]
	if len(payload) > 0 {
		buf.Write(payload) // offset 96, variable data
	}
	return buf.Bytes()
}

// ipv4Bytes returns a 16-byte array with an IPv4 address in the first 4 bytes.
func ipv4Bytes(a, b, c, d byte) [16]byte {
	var ip [16]byte
	ip[0], ip[1], ip[2], ip[3] = a, b, c, d
	return ip
}

// ipv6Bytes returns a 16-byte array from a full IPv6 address.
func ipv6Bytes(b [16]byte) [16]byte { return b }

// commBytes returns a 16-byte comm array from a string.
func commBytes(s string) [16]byte {
	var c [16]byte
	copy(c[:], s)
	return c
}

// ── DecodeFromBytes ──────────────────────────────────────────────────────────

func TestGoTLSDataEvent_DecodeFromBytes_IPv4_Write(t *testing.T) {
	srcIP := ipv4Bytes(192, 168, 1, 10)
	dstIP := ipv4Bytes(10, 0, 0, 1)
	payload := []byte("GET / HTTP/1.1\r\n")

	raw := buildEventBytes(t,
		1000000, 1, 0, 42, 99, int32(len(payload)), 0, // eventType=WRITE
		7, srcIP, 12345, dstIP, 443, 4, // ipVersion=4
		commBytes("curl"), payload,
	)

	var e GoTLSDataEvent
	if err := e.DecodeFromBytes(raw); err != nil {
		t.Fatalf("DecodeFromBytes error: %v", err)
	}

	if e.Timestamp != 1000000 {
		t.Errorf("Timestamp = %d, want 1000000", e.Timestamp)
	}
	if e.Seq != 1 {
		t.Errorf("Seq = %d, want 1", e.Seq)
	}
	if e.EmitCPU != 0 {
		t.Errorf("EmitCPU = %d, want 0", e.EmitCPU)
	}
	if e.Pid != 42 {
		t.Errorf("Pid = %d, want 42", e.Pid)
	}
	if e.Tid != 99 {
		t.Errorf("Tid = %d, want 99", e.Tid)
	}
	if e.DataLen != int32(len(payload)) {
		t.Errorf("DataLen = %d, want %d", e.DataLen, len(payload))
	}
	if e.EventType != 0 {
		t.Errorf("EventType = %d, want 0 (WRITE)", e.EventType)
	}
	if e.Fd != 7 {
		t.Errorf("Fd = %d, want 7", e.Fd)
	}
	if e.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", e.SrcPort)
	}
	if e.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", e.DstPort)
	}
	if e.IPVersion != 4 {
		t.Errorf("IPVersion = %d, want 4", e.IPVersion)
	}
	if e.GetComm() != "curl" {
		t.Errorf("Comm = %q, want \"curl\"", e.GetComm())
	}
	if string(e.GetData()) != string(payload) {
		t.Errorf("Data = %q, want %q", string(e.GetData()), string(payload))
	}
	if e.GetSrcIP() != "192.168.1.10" {
		t.Errorf("SrcIP = %q, want \"192.168.1.10\"", e.GetSrcIP())
	}
	if e.GetDstIP() != "10.0.0.1" {
		t.Errorf("DstIP = %q, want \"10.0.0.1\"", e.GetDstIP())
	}
}

func TestGoTLSDataEvent_DecodeFromBytes_IPv4_Read(t *testing.T) {
	srcIP := ipv4Bytes(10, 0, 0, 1)
	dstIP := ipv4Bytes(192, 168, 1, 10)
	payload := []byte("HTTP/1.1 200 OK\r\n")

	raw := buildEventBytes(t,
		2000000, 2, 0, 100, 200, int32(len(payload)), 1, // eventType=READ
		5, srcIP, 443, dstIP, 54321, 4,
		commBytes("myapp"), payload,
	)

	var e GoTLSDataEvent
	if err := e.DecodeFromBytes(raw); err != nil {
		t.Fatalf("DecodeFromBytes error: %v", err)
	}
	if e.EventType != 1 {
		t.Errorf("EventType = %d, want 1 (READ)", e.EventType)
	}
	if !e.IsRead() {
		t.Error("IsRead() should be true")
	}
	if e.IsWrite() {
		t.Error("IsWrite() should be false")
	}
}

func TestGoTLSDataEvent_DecodeFromBytes_IPv6(t *testing.T) {
	// 2001:db8::1
	var src6 [16]byte
	src6[0], src6[1] = 0x20, 0x01
	src6[2], src6[3] = 0x0d, 0xb8
	src6[15] = 0x01
	// fe80::1
	var dst6 [16]byte
	dst6[0], dst6[1] = 0xfe, 0x80
	dst6[15] = 0x01

	payload := []byte("hello")
	raw := buildEventBytes(t,
		3000000, 3, 0, 7, 8, int32(len(payload)), 0,
		3, ipv6Bytes(src6), 8080, ipv6Bytes(dst6), 9090, 6, // ipVersion=6
		commBytes("server"), payload,
	)

	var e GoTLSDataEvent
	if err := e.DecodeFromBytes(raw); err != nil {
		t.Fatalf("DecodeFromBytes error: %v", err)
	}
	if e.IPVersion != 6 {
		t.Errorf("IPVersion = %d, want 6", e.IPVersion)
	}
	if e.GetSrcIP() != "2001:db8::1" {
		t.Errorf("SrcIP = %q, want \"2001:db8::1\"", e.GetSrcIP())
	}
	if e.GetDstIP() != "fe80::1" {
		t.Errorf("DstIP = %q, want \"fe80::1\"", e.GetDstIP())
	}
}

func TestGoTLSDataEvent_DecodeFromBytes_ZeroDataLen(t *testing.T) {
	raw := buildEventBytes(t,
		1000, 4, 0, 1, 2, 0, 0, // dataLen=0
		1, ipv4Bytes(1, 2, 3, 4), 100, ipv4Bytes(5, 6, 7, 8), 200, 4,
		commBytes("app"), nil,
	)
	var e GoTLSDataEvent
	if err := e.DecodeFromBytes(raw); err != nil {
		t.Fatalf("DecodeFromBytes error: %v", err)
	}
	if e.DataLen != 0 {
		t.Errorf("DataLen = %d, want 0", e.DataLen)
	}
	if len(e.GetData()) != 0 {
		t.Errorf("GetData() length = %d, want 0", len(e.GetData()))
	}
}

func TestGoTLSDataEvent_DecodeFromBytes_TimestampZeroFallback(t *testing.T) {
	raw := buildEventBytes(t,
		0, 5, 0, 1, 2, 0, 0, // timestamp=0 → should be filled by time.Now()
		1, ipv4Bytes(1, 2, 3, 4), 80, ipv4Bytes(5, 6, 7, 8), 8080, 4,
		commBytes("app"), nil,
	)
	before := uint64(time.Now().UnixNano())
	var e GoTLSDataEvent
	if err := e.DecodeFromBytes(raw); err != nil {
		t.Fatalf("DecodeFromBytes error: %v", err)
	}
	after := uint64(time.Now().UnixNano())
	if e.Timestamp < before || e.Timestamp > after {
		t.Errorf("Timestamp %d should be between %d and %d", e.Timestamp, before, after)
	}
}

func TestGoTLSDataEvent_DecodeFromBytes_TruncatedInput(t *testing.T) {
	// Only 10 bytes — far too short to decode even the first field fully
	var e GoTLSDataEvent
	err := e.DecodeFromBytes(make([]byte, 10))
	if err == nil {
		t.Error("expected error for truncated input, got nil")
	}
}

func TestGoTLSDataEvent_DecodeFromBytes_DataLenExceedsBuffer(t *testing.T) {
	// claim dataLen=100 but provide no payload bytes
	raw := buildEventBytes(t,
		1000, 6, 0, 1, 2, 100, 0, // dataLen=100
		1, ipv4Bytes(1, 2, 3, 4), 80, ipv4Bytes(5, 6, 7, 8), 8080, 4,
		commBytes("app"), nil, // no payload
	)
	var e GoTLSDataEvent
	err := e.DecodeFromBytes(raw)
	if err == nil {
		t.Error("expected error when dataLen exceeds buffer, got nil")
	}
}

// ── tuple() ─────────────────────────────────────────────────────────────────

func TestGoTLSDataEvent_tuple_IPv4(t *testing.T) {
	e := &GoTLSDataEvent{
		SrcIP:     ipv4Bytes(192, 168, 1, 1),
		SrcPort:   12345,
		DstIP:     ipv4Bytes(10, 0, 0, 1),
		DstPort:   443,
		IPVersion: 4,
	}
	got := e.GetTuple()
	want := "[192.168.1.1]:12345->[10.0.0.1]:443"
	if got != want {
		t.Errorf("tuple() = %q, want %q", got, want)
	}
}

func TestGoTLSDataEvent_tuple_IPv6(t *testing.T) {
	var src6, dst6 [16]byte
	// ::1 (loopback)
	src6[15] = 1
	// ::2
	dst6[15] = 2

	e := &GoTLSDataEvent{
		SrcIP:     src6,
		SrcPort:   8080,
		DstIP:     dst6,
		DstPort:   9090,
		IPVersion: 6,
	}
	got := e.GetTuple()
	want := "[::1]:8080->[::2]:9090"
	if got != want {
		t.Errorf("tuple() = %q, want %q", got, want)
	}
}

func TestGoTLSDataEvent_tuple_UnknownVersion(t *testing.T) {
	e := &GoTLSDataEvent{IPVersion: 0}
	if got := e.GetTuple(); got != DefaultTuple {
		t.Errorf("tuple() with unknown version = %q, want %q", got, DefaultTuple)
	}
}

// ── String() / StringHex() ───────────────────────────────────────────────────

func TestGoTLSDataEvent_String_IPv4_Write(t *testing.T) {
	e := &GoTLSDataEvent{
		Pid:       1234,
		Tid:       5678,
		Fd:        3,
		DataLen:   5,
		EventType: 0,
		SrcIP:     ipv4Bytes(1, 2, 3, 4),
		SrcPort:   1111,
		DstIP:     ipv4Bytes(5, 6, 7, 8),
		DstPort:   443,
		IPVersion: 4,
		Data:      []byte("hello"),
	}
	copy(e.Comm[:], "curl")

	s := e.String()
	for _, want := range []string{"PID:1234", "TID:5678", "WRITE", "[1.2.3.4]:1111", "[5.6.7.8]:443", "hello"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q, got: %s", want, s)
		}
	}
}

func TestGoTLSDataEvent_String_IPv6_Read(t *testing.T) {
	var src6, dst6 [16]byte
	src6[15] = 1
	dst6[15] = 2

	e := &GoTLSDataEvent{
		Pid:       99,
		Tid:       100,
		Fd:        5,
		DataLen:   5,
		EventType: 1, // READ
		SrcIP:     src6,
		SrcPort:   9000,
		DstIP:     dst6,
		DstPort:   443,
		IPVersion: 6,
		Data:      []byte("world"),
	}
	copy(e.Comm[:], "go")

	s := e.String()
	for _, want := range []string{"PID:99", "READ", "[::1]:9000", "[::2]:443", "world"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q, got: %s", want, s)
		}
	}
}

func TestGoTLSDataEvent_String_NoTuple(t *testing.T) {
	e := &GoTLSDataEvent{
		Pid:       1,
		DataLen:   3,
		EventType: 0,
		IPVersion: 0, // unknown → DefaultTuple
		Data:      []byte("abc"),
	}
	s := e.String()
	// unknown IP version falls back to DefaultTuple, so Tuple: should appear
	if !strings.Contains(s, "Tuple:") {
		t.Errorf("String() should contain Tuple: with DefaultTuple for unknown IP version, got: %s", s)
	}
	if !strings.Contains(s, DefaultTuple) {
		t.Errorf("String() should contain DefaultTuple %q, got: %s", DefaultTuple, s)
	}
}

func TestGoTLSDataEvent_StringHex(t *testing.T) {
	e := &GoTLSDataEvent{
		Pid:       1,
		DataLen:   4,
		EventType: 0,
		IPVersion: 0,
		Data:      []byte("test"),
	}
	h := e.StringHex()
	if !strings.Contains(h, "hex") {
		t.Errorf("StringHex() should contain 'hex', got: %s", h)
	}
	// hex encoding of "test" = 74657374
	if !strings.Contains(h, "74657374") {
		t.Errorf("StringHex() should contain hex of 'test', got: %s", h)
	}
}

// ── UUID() ───────────────────────────────────────────────────────────────────

func TestGoTLSDataEvent_UUID_IPv4(t *testing.T) {
	e := &GoTLSDataEvent{
		Pid:       1234,
		Tid:       5678,
		Fd:        3,
		Timestamp: 9999,
		SrcIP:     ipv4Bytes(1, 2, 3, 4),
		SrcPort:   1111,
		DstIP:     ipv4Bytes(5, 6, 7, 8),
		DstPort:   443,
		IPVersion: 4,
	}
	copy(e.Comm[:], "curl")
	uuid := e.UUID()
	for _, want := range []string{"gotls:", "1234", "curl", "3", "[1.2.3.4]"} {
		if !strings.Contains(uuid, want) {
			t.Errorf("UUID() missing %q, got: %s", want, uuid)
		}
	}
}

func TestGoTLSDataEvent_UUID_IPv6(t *testing.T) {
	var src6, dst6 [16]byte
	src6[15] = 1
	dst6[15] = 2

	e := &GoTLSDataEvent{
		Pid:       99,
		Tid:       100,
		Fd:        5,
		Timestamp: 12345,
		SrcIP:     src6,
		SrcPort:   8080,
		DstIP:     dst6,
		DstPort:   9090,
		IPVersion: 6,
	}
	copy(e.Comm[:], "server")
	uuid := e.UUID()
	for _, want := range []string{"gotls:", "99", "server", "5", "::1"} {
		if !strings.Contains(uuid, want) {
			t.Errorf("UUID() missing %q, got: %s", want, uuid)
		}
	}
}

// ── Clone / Type / Validate ─────────────────────────────────────────────────

func TestGoTLSDataEvent_Clone(t *testing.T) {
	e := &GoTLSDataEvent{Pid: 1, DataLen: 3, Data: []byte("abc")}
	cloned := e.Clone()
	if cloned == nil {
		t.Fatal("Clone() returned nil")
	}
	if _, ok := cloned.(*GoTLSDataEvent); !ok {
		t.Fatal("Clone() did not return *GoTLSDataEvent")
	}
}

func TestGoTLSDataEvent_Type(t *testing.T) {
	e := &GoTLSDataEvent{}
	if e.Type() != domain.EventTypeOutput {
		t.Errorf("Type() = %v, want EventTypeOutput", e.Type())
	}
}

func TestGoTLSDataEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *GoTLSDataEvent
		wantErr bool
	}{
		{
			name:    "valid zero dataLen",
			event:   &GoTLSDataEvent{DataLen: 0},
			wantErr: false,
		},
		{
			name:    "valid max dataLen",
			event:   &GoTLSDataEvent{DataLen: 16 * 1024},
			wantErr: false,
		},
		{
			name:    "negative dataLen",
			event:   &GoTLSDataEvent{DataLen: -1},
			wantErr: true,
		},
		{
			name:    "exceeds max dataLen",
			event:   &GoTLSDataEvent{DataLen: 16*1024 + 1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ── helper functions ─────────────────────────────────────────────────────────

func Test_commToString_GoTLS(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"null-terminated", []byte{'a', 'p', 'p', 0, 0, 0}, "app"},
		{"no null", []byte{'g', 'o'}, "go"},
		{"empty", []byte{}, ""},
		{"all null", []byte{0, 0, 0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commToString(tt.data); got != tt.want {
				t.Errorf("commToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_ipToString_GoTLS(t *testing.T) {
	tests := []struct {
		name    string
		ip      []byte
		version uint8
		want    string
	}{
		{"ipv4", []byte{192, 168, 1, 1}, 4, "192.168.1.1"},
		{"ipv6 loopback", func() []byte { b := make([]byte, 16); b[15] = 1; return b }(), 6, "::1"},
		{"unknown version", []byte{1, 2, 3, 4}, 0, ""},
		{"ipv4 too short", []byte{1, 2}, 4, ""},
		{"ipv6 too short", make([]byte, 8), 6, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipToString(tt.ip, tt.version); got != tt.want {
				t.Errorf("ipToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── IsRead / IsWrite ─────────────────────────────────────────────────────────

func TestGoTLSDataEvent_IsReadWrite(t *testing.T) {
	write := &GoTLSDataEvent{EventType: 0}
	if !write.IsWrite() {
		t.Error("IsWrite() should be true for EventType=0")
	}
	if write.IsRead() {
		t.Error("IsRead() should be false for EventType=0")
	}

	read := &GoTLSDataEvent{EventType: 1}
	if !read.IsRead() {
		t.Error("IsRead() should be true for EventType=1")
	}
	if read.IsWrite() {
		t.Error("IsWrite() should be false for EventType=1")
	}
}

// ── GetData / GetDataLen ─────────────────────────────────────────────────────

func TestGoTLSDataEvent_GetData(t *testing.T) {
	e := &GoTLSDataEvent{
		DataLen: 5,
		Data:    []byte("hello world"),
	}
	got := e.GetData()
	if string(got) != "hello" {
		t.Errorf("GetData() = %q, want \"hello\"", string(got))
	}
}

func TestGoTLSDataEvent_GetDataLen_Negative(t *testing.T) {
	e := &GoTLSDataEvent{DataLen: -5}
	if e.GetDataLen() != 0 {
		t.Errorf("GetDataLen() with negative = %d, want 0", e.GetDataLen())
	}
}

// ── DecodeFromBytes round-trip ───────────────────────────────────────────────

func TestGoTLSDataEvent_DecodeFromBytes_RoundTrip(t *testing.T) {
	wantPayload := []byte("POST /upload HTTP/1.1\r\n")
	var comm [16]byte
	copy(comm[:], "myservice")

	raw := buildEventBytes(t,
		999888777, 7, 0, 12345, 67890, int32(len(wantPayload)), 0,
		8, ipv4Bytes(172, 16, 0, 1), 54321, ipv4Bytes(172, 16, 0, 2), 443, 4,
		comm, wantPayload,
	)

	var e GoTLSDataEvent
	if err := e.DecodeFromBytes(raw); err != nil {
		t.Fatalf("DecodeFromBytes error: %v", err)
	}

	if e.Seq != 7 {
		t.Errorf("Seq = %d, want 7", e.Seq)
	}
	if e.EmitCPU != 0 {
		t.Errorf("EmitCPU = %d, want 0", e.EmitCPU)
	}
	if e.Pid != 12345 {
		t.Errorf("Pid = %d, want 12345", e.Pid)
	}
	if e.Tid != 67890 {
		t.Errorf("Tid = %d, want 67890", e.Tid)
	}
	if e.Fd != 8 {
		t.Errorf("Fd = %d, want 8", e.Fd)
	}
	if e.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", e.SrcPort)
	}
	if e.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", e.DstPort)
	}
	if e.IPVersion != 4 {
		t.Errorf("IPVersion = %d, want 4", e.IPVersion)
	}
	if e.GetSrcIP() != "172.16.0.1" {
		t.Errorf("SrcIP = %q, want \"172.16.0.1\"", e.GetSrcIP())
	}
	if e.GetDstIP() != "172.16.0.2" {
		t.Errorf("DstIP = %q, want \"172.16.0.2\"", e.GetDstIP())
	}
	if e.GetComm() != "myservice" {
		t.Errorf("Comm = %q, want \"myservice\"", e.GetComm())
	}
	if string(e.GetData()) != string(wantPayload) {
		t.Errorf("Data = %q, want %q", string(e.GetData()), string(wantPayload))
	}
	if e.GetTuple() != "[172.16.0.1]:54321->[172.16.0.2]:443" {
		t.Errorf("tuple() = %q, want \"[172.16.0.1]:54321->[172.16.0.2]:443\"", e.GetTuple())
	}
}
