// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package openssl

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// buildConnPayload builds a 90-byte payload that matches the C struct connect_event_t
// layout (with __attribute__((packed))):
//
//	unsigned __int128 saddr   → 16 bytes
//	unsigned __int128 daddr   → 16 bytes
//	char comm[16]             → 16 bytes
//	u64 timestamp_ns          →  8 bytes
//	u64 sock                  →  8 bytes
//	u32 pid                   →  4 bytes
//	u32 tid                   →  4 bytes
//	u32 fd                    →  4 bytes
//	u16 family                →  2 bytes
//	u16 sport                 →  2 bytes
//	u16 dport                 →  2 bytes
//	u8  is_destroy            →  1 byte
//	u8  pad[7]                →  7 bytes
//	Total                     → 90 bytes
func buildConnPayload(t *testing.T,
	saddr [16]byte, daddr [16]byte,
	comm [16]byte,
	timestampNs uint64, sock uint64,
	pid, tid, fd uint32,
	family, sport, dport uint16,
	isDestroy uint8,
) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	write := func(v any) {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			t.Fatalf("buildConnPayload: binary.Write failed: %v", err)
		}
	}
	write(saddr)
	write(daddr)
	write(comm)
	write(timestampNs)
	write(sock)
	write(pid)
	write(tid)
	write(fd)
	write(family)
	write(sport)
	write(dport)
	write(isDestroy)
	write([7]byte{}) // pad
	if buf.Len() != 90 {
		t.Fatalf("buildConnPayload: expected 90 bytes, got %d", buf.Len())
	}
	return buf.Bytes()
}

// TestConnDataEvent_DecodeFromBytes_IPv4 verifies that a 90-byte eBPF payload
// (matching the C struct connect_event_t size) is decoded correctly for IPv4.
// This is the regression test for the "unexpected EOF at Sock" bug, which was
// caused by Saddr/Daddr being [32]byte instead of [16]byte (the C struct uses
// unsigned __int128 = 16 bytes per address).
func TestConnDataEvent_DecodeFromBytes_IPv4(t *testing.T) {
	var saddr [16]byte
	// IPv4 127.0.0.1 stored in the first 4 bytes (little-endian, as written by kernel)
	saddr[0], saddr[1], saddr[2], saddr[3] = 127, 0, 0, 1

	var daddr [16]byte
	// IPv4 8.8.8.8
	daddr[0], daddr[1], daddr[2], daddr[3] = 8, 8, 8, 8

	var comm [16]byte
	copy(comm[:], "curl")

	payload := buildConnPayload(t,
		saddr, daddr, comm,
		1234567890,    // timestampNs
		0xdeadbeef,    // sock
		1001, 1002, 5, // pid, tid, fd
		unix.AF_INET, 54321, 443, // family, sport, dport
		0, // isDestroy
	)

	event := &ConnDataEvent{}
	if err := event.DecodeFromBytes(payload); err != nil {
		t.Fatalf("DecodeFromBytes failed (90-byte payload): %v", err)
	}

	if event.TimestampNs != 1234567890 {
		t.Errorf("TimestampNs = %d, want 1234567890", event.TimestampNs)
	}
	if event.Sock != 0xdeadbeef {
		t.Errorf("Sock = %#x, want 0xdeadbeef", event.Sock)
	}
	if event.Pid != 1001 {
		t.Errorf("Pid = %d, want 1001", event.Pid)
	}
	if event.Tid != 1002 {
		t.Errorf("Tid = %d, want 1002", event.Tid)
	}
	if event.Fd != 5 {
		t.Errorf("Fd = %d, want 5", event.Fd)
	}
	if event.Family != unix.AF_INET {
		t.Errorf("Family = %d, want AF_INET (%d)", event.Family, unix.AF_INET)
	}
	if event.Sport != 54321 {
		t.Errorf("Sport = %d, want 54321", event.Sport)
	}
	if event.Dport != 443 {
		t.Errorf("Dport = %d, want 443", event.Dport)
	}
	if event.IsDestroy != 0 {
		t.Errorf("IsDestroy = %d, want 0", event.IsDestroy)
	}

	// Verify tuple is populated with IP addresses
	if event.Tuple == "" {
		t.Error("Tuple should not be empty for AF_INET")
	}
	if !strings.Contains(event.Tuple, "127.0.0.1") {
		t.Errorf("Tuple should contain src IP 127.0.0.1, got: %s", event.Tuple)
	}
	if !strings.Contains(event.Tuple, "8.8.8.8") {
		t.Errorf("Tuple should contain dst IP 8.8.8.8, got: %s", event.Tuple)
	}
	if !strings.Contains(event.Tuple, "443") {
		t.Errorf("Tuple should contain dst port 443, got: %s", event.Tuple)
	}
}

// TestConnDataEvent_DecodeFromBytes_IPv6 verifies that a 90-byte eBPF payload
// is decoded correctly for IPv6. The kernel stores the full 128-bit IPv6
// address in bytes 0-15 of the unsigned __int128 field (not bytes 16-31 as
// the old [32]byte code assumed).
func TestConnDataEvent_DecodeFromBytes_IPv6(t *testing.T) {
	var saddr [16]byte
	// ::1 (loopback) in network byte order
	saddr[15] = 1

	var daddr [16]byte
	// 2001:4860:4860::8888 (Google DNS)
	daddr[0] = 0x20
	daddr[1] = 0x01
	daddr[2] = 0x48
	daddr[3] = 0x60
	daddr[4] = 0x48
	daddr[5] = 0x60
	daddr[14] = 0x88
	daddr[15] = 0x88

	var comm [16]byte
	copy(comm[:], "wget")

	payload := buildConnPayload(t,
		saddr, daddr, comm,
		9876543210,    // timestampNs
		0xcafebabe,    // sock
		2001, 2002, 7, // pid, tid, fd
		unix.AF_INET6, 12345, 443, // family, sport, dport
		1, // isDestroy
	)

	event := &ConnDataEvent{}
	if err := event.DecodeFromBytes(payload); err != nil {
		t.Fatalf("DecodeFromBytes failed (90-byte IPv6 payload): %v", err)
	}

	if event.Family != unix.AF_INET6 {
		t.Errorf("Family = %d, want AF_INET6 (%d)", event.Family, unix.AF_INET6)
	}
	if event.IsDestroy != 1 {
		t.Errorf("IsDestroy = %d, want 1", event.IsDestroy)
	}
	if event.Tuple == "" {
		t.Error("Tuple should not be empty for AF_INET6")
	}
	if !strings.Contains(event.Tuple, "443") {
		t.Errorf("Tuple should contain port 443, got: %s", event.Tuple)
	}
}

// TestConnDataEvent_DecodeFromBytes_ShortPayload verifies that a payload
// shorter than the C struct (which was the original [32]byte bug scenario)
// returns an appropriate error instead of silently reading garbage.
func TestConnDataEvent_DecodeFromBytes_ShortPayload(t *testing.T) {
	// A 90-byte payload truncated to 50 bytes should fail gracefully.
	var saddr [16]byte
	var daddr [16]byte
	var comm [16]byte

	fullPayload := buildConnPayload(t,
		saddr, daddr, comm,
		0, 0, 0, 0, 0,
		unix.AF_INET, 0, 0, 0,
	)

	shortPayload := fullPayload[:50]
	event := &ConnDataEvent{}
	err := event.DecodeFromBytes(shortPayload)
	if err == nil {
		t.Error("DecodeFromBytes should return an error for a truncated payload")
	}
}
