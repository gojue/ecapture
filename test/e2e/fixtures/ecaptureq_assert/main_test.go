// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
)

func TestValidateProcess(t *testing.T) {
	const expected = int64(2341289)
	for _, tt := range []struct {
		name      string
		pid       int64
		process   string
		args      string
		truncated bool
		wantError bool
	}{
		{"kernel TGID", expected, "openssl_client", "client\x00private-token\x00", false, false},
		{"namespace PID", 14287, "openssl_client", "client\x00private-token\x00", false, true},
		{"unknown PID", 0, "openssl_client", "client\x00private-token\x00", false, true},
		{"unknown name", expected, "", "client\x00private-token\x00", false, true},
		{"placeholder name", expected, "decryptor", "client\x00private-token\x00", false, true},
		{"missing argv", expected, "openssl_client", "", false, true},
		{"wrong argv", expected, "openssl_client", "client\x00different-secret\x00", false, true},
		{"truncated argv", expected, "openssl_client", "client\x00private-token\x00", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProcess(&pb.Event{Pid: tt.pid, Pname: tt.process, ProcessArgs: []byte(tt.args), ProcessArgsTruncated: tt.truncated}, expected, "private-token")
			if (err != nil) != tt.wantError {
				t.Fatalf("validateProcess error=%v, wantError=%v", err, tt.wantError)
			}
			if err != nil && (strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "different-secret")) {
				t.Fatal("diagnostic leaked argv")
			}
		})
	}
	if err := validateProcess(&pb.Event{Pid: 0, Pname: "openssl_client"}, 0, ""); err == nil {
		t.Fatal("zero expected PID must fail")
	}
}
