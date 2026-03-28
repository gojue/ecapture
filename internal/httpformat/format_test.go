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

package httpformat

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestFormatPayload_HTTPRequest(t *testing.T) {
	raw := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n\r\n"
	result := FormatPayload([]byte(raw))

	if !strings.Contains(result, "GET /index.html HTTP/1.1") {
		t.Errorf("expected formatted HTTP request line, got:\n%s", result)
	}
	if !strings.Contains(result, "Host: example.com") {
		t.Errorf("expected Host header, got:\n%s", result)
	}
}

func TestFormatPayload_HTTPResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"
	result := FormatPayload([]byte(raw))

	if !strings.Contains(result, "HTTP/1.1 200 OK") {
		t.Errorf("expected HTTP response status, got:\n%s", result)
	}
	if !strings.Contains(result, "Content-Type: text/html") {
		t.Errorf("expected Content-Type header, got:\n%s", result)
	}
	if !strings.Contains(result, "Hello, World!") {
		t.Errorf("expected response body, got:\n%s", result)
	}
}

func TestFormatPayload_HTTPResponseGzip(t *testing.T) {
	body := "Hello, Gzip World!"
	var gzBody bytes.Buffer
	gz := gzip.NewWriter(&gzBody)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	var raw bytes.Buffer
	raw.WriteString("HTTP/1.1 200 OK\r\n")
	raw.WriteString("Content-Encoding: gzip\r\n")
	raw.WriteString("Content-Type: text/html\r\n")
	raw.WriteString("\r\n")
	raw.Write(gzBody.Bytes())

	result := FormatPayload(raw.Bytes())

	if !strings.Contains(result, "HTTP/1.1 200 OK") {
		t.Errorf("expected HTTP status, got:\n%s", result)
	}
	if !strings.Contains(result, body) {
		t.Errorf("expected decompressed body %q, got:\n%s", body, result)
	}
}

func TestFormatPayload_TruncatedResponse(t *testing.T) {
	// Simulate a response whose body is shorter than Content-Length
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: text/html\r\n\r\nPartial body"
	result := FormatPayload([]byte(raw))

	if !strings.Contains(result, "HTTP/1.1 200 OK") {
		t.Errorf("expected HTTP status, got:\n%s", result)
	}
	if !strings.Contains(result, "Partial body") {
		t.Errorf("expected partial body in output, got:\n%s", result)
	}
}

func TestFormatPayload_NonHTTP(t *testing.T) {
	raw := "This is just some random TLS data, not HTTP."
	result := FormatPayload([]byte(raw))
	if result != raw {
		t.Errorf("expected raw fallback, got:\n%s", result)
	}
}

func TestFormatPayload_Binary(t *testing.T) {
	raw := []byte{0x16, 0x03, 0x01, 0x00, 0x05}
	result := FormatPayload(raw)
	if result != string(raw) {
		t.Errorf("expected raw fallback for binary data")
	}
}

func TestFormatPayload_Empty(t *testing.T) {
	result := FormatPayload(nil)
	if result != "" {
		t.Errorf("expected empty string, got: %q", result)
	}
	result = FormatPayload([]byte{})
	if result != "" {
		t.Errorf("expected empty string, got: %q", result)
	}
}

func TestFormatPayload_POSTRequest(t *testing.T) {
	raw := "POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"key\": \"value\"}"
	result := FormatPayload([]byte(raw))

	if !strings.Contains(result, "POST /api/data HTTP/1.1") {
		t.Errorf("expected POST request line, got:\n%s", result)
	}
	if !strings.Contains(result, `{"key": "value"}`) {
		t.Errorf("expected JSON body, got:\n%s", result)
	}
}
