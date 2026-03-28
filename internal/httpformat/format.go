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

// Package httpformat provides HTTP-aware formatting for captured TLS plaintext.
// When captured HTTPS data contains HTTP requests or responses, this package
// parses and formats them with proper HTTP structure (headers, decompressed body).
// For non-HTTP data, it falls back to raw string output.
package httpformat

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
)

// FormatPayload attempts to detect and format the data as an HTTP request or
// response. If the data does not look like HTTP, the raw bytes are returned
// as a plain string.
func FormatPayload(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Try HTTP request first (e.g. "GET / HTTP/1.1\r\n...")
	if s, ok := tryFormatHTTPRequest(data); ok {
		return s
	}

	// Try HTTP response (e.g. "HTTP/1.1 200 OK\r\n...")
	if s, ok := tryFormatHTTPResponse(data); ok {
		return s
	}

	// Fallback: return raw payload as string
	return string(data)
}

// tryFormatHTTPRequest parses data as an HTTP/1.x request and returns
// the formatted output. Returns ("", false) when parsing fails.
func tryFormatHTTPRequest(data []byte) (string, bool) {
	rd := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(rd)
	if err != nil {
		return "", false
	}
	defer req.Body.Close()

	// HTTP/2.0 is not handled by net/http parser – fall through.
	if req.Proto == "HTTP/2.0" {
		return "", false
	}

	// Read body (may be truncated for large payloads captured in a single event).
	rawBody, bodyErr := io.ReadAll(req.Body)
	switch {
	case bodyErr == nil:
		// full body read
	case errors.Is(bodyErr, io.ErrUnexpectedEOF):
		// truncated but we still have partial data – that's fine
	default:
		return "", false
	}

	// Decompress gzip body if needed.
	rawBody = decompressGzip(req.Header.Get("Content-Encoding"), rawBody)

	// Dump headers only (body=false) then manually append body so
	// truncated payloads are still shown.
	header, err := httputil.DumpRequest(req, false)
	if err != nil {
		return "", false
	}
	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(rawBody)
	return buf.String(), true
}

// tryFormatHTTPResponse parses data as an HTTP/1.x response and returns
// the formatted output. Returns ("", false) when parsing fails.
func tryFormatHTTPResponse(data []byte) (string, bool) {
	rd := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(rd, nil)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	// Read body (may be truncated).
	rawBody, bodyErr := io.ReadAll(resp.Body)
	switch {
	case bodyErr == nil:
		// full body read
	case errors.Is(bodyErr, io.ErrUnexpectedEOF):
		// truncated payload
	default:
		return "", false
	}

	// Decompress gzip body if needed.
	rawBody = decompressGzip(resp.Header.Get("Content-Encoding"), rawBody)

	// Dump headers only then append body.
	header, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return "", false
	}
	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(rawBody)
	return buf.String(), true
}

// decompressGzip attempts to decompress gzip-encoded data. Returns the
// original data on any failure.
func decompressGzip(contentEncoding string, data []byte) []byte {
	if contentEncoding != "gzip" || len(data) == 0 {
		return data
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	defer r.Close()
	decompressed, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return decompressed
}
