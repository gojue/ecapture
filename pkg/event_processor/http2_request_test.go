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

package event_processor

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

func TestHttp2RequestParser(t *testing.T) {
	h2File := "testdata/952293616935738.bin"
	httpBody, err := os.ReadFile(h2File)
	if err != nil {
		t.Fatalf("TestHttp2RequestParser: read payload file error: %s, file:%s", err.Error(), h2File)
	}

	h2r := &HTTP2Request{}
	h2r.Init()
	err = h2r.detect(httpBody)
	if err != nil {
		t.Fatalf("TestHttp2RequestParser: detect http request failed: %s", err.Error())
	}
	i, e := h2r.Write(httpBody)
	if e != nil {
		t.Errorf("TestHttp2RequestParser: write http request failed: %s", e.Error())
	}
	t.Logf("TestHttp2RequestParser: wrot body:%d", i)

	_, err = h2r.bufReader.Discard(ClientPrefaceLen)
	if err != nil {
		t.Logf("[http2 request] Discard HTTP2 Magic error:%s", err.Error())
	}
	var frameTypes = make([]string, 0)
	for {
		f, err := h2r.framer.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("[http2 response] read http2 response frame error:%s", err.Error())
			}
			break
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			t.Logf("TestHttp2RequestParser: frame type:%s", f.Type)
			frameTypes = append(frameTypes, f.Type.String())
		case *http2.DataFrame:
			t.Logf("TestHttp2RequestParser: frame type:%s", f.Type)
			frameTypes = append(frameTypes, f.Type.String())
		default:
			fh := f.Header()
			frameTypes = append(frameTypes, fh.Type.String())
			t.Logf("TestHttp2RequestParser: Frame Type\t=>\t%s", fh.Type.String())
		}
	}
	if len(frameTypes) != 5 {
		t.Fatalf("TestHttp2ResponseParser: frameTypes length error, want: 5, got:%d", len(frameTypes))
	}
}

// TestHttp2RequestDisplayWithIncompleteFrame tests that Display() handles incomplete frames
// gracefully without logging errors. This simulates the scenario described in the issue where
// truncated TLS data causes io.ErrUnexpectedEOF during streaming capture.
func TestHttp2RequestDisplayWithIncompleteFrame(t *testing.T) {
	h2File := "testdata/952293616935738.bin"
	httpBody, err := os.ReadFile(h2File)
	if err != nil {
		t.Fatalf("read payload file error: %s, file:%s", err.Error(), h2File)
	}

	// Truncate the data to simulate incomplete frame (cut in the middle of a frame)
	// Keep the client preface and part of the frames
	truncatedData := httpBody[:len(httpBody)/2]

	h2r := &HTTP2Request{}
	h2r.Init()

	// Verify truncated data can still be detected as HTTP2 request
	err = h2r.detect(truncatedData)
	if err != nil {
		t.Fatalf("detect http request failed: %s", err.Error())
	}

	_, err = h2r.Write(truncatedData)
	if err != nil {
		t.Fatalf("write http request failed: %s", err.Error())
	}

	// Capture log output to verify no error is logged for io.ErrUnexpectedEOF
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	// Display should handle incomplete frames gracefully
	result := h2r.Display()

	// Verify that no error log was produced for "unexpected EOF"
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "unexpected EOF") {
		t.Errorf("Display() should not log 'unexpected EOF' error for incomplete frames, got log: %s", logOutput)
	}

	// Display should still return partial data (frames that were complete)
	if len(result) == 0 {
		t.Log("Display returned empty result, which is acceptable for incomplete data")
	} else {
		t.Logf("Display returned %d bytes of parsed data", len(result))
	}
}

// TestHttp2RequestDisplayWithMinimalIncompleteFrame tests Display() with data that has
// a valid HTTP/2 client preface followed by an incomplete frame.
func TestHttp2RequestDisplayWithMinimalIncompleteFrame(t *testing.T) {
	// Create HTTP/2 client preface followed by incomplete SETTINGS frame
	// Client preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	clientPreface := []byte(http2.ClientPreface)

	// Incomplete SETTINGS frame header that claims 18 bytes (0x12 hex) payload
	// but we only provide the header without the payload data
	incompleteFrame := []byte{
		0x00, 0x00, 0x12, // Length: 18 bytes (0x12 hex) - payload not provided
		0x04,             // Type: SETTINGS
		0x00,             // Flags: none
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		// Missing payload - this will cause io.ErrUnexpectedEOF
	}

	testData := append(clientPreface, incompleteFrame...)

	h2r := &HTTP2Request{}
	h2r.Init()

	// Verify detection passes
	err := h2r.detect(testData)
	if err != nil {
		t.Fatalf("detect should pass: %s", err.Error())
	}

	_, err = h2r.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %s", err.Error())
	}

	// Capture log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	// Display should not panic and should not log error for incomplete frame
	result := h2r.Display()

	logOutput := logBuf.String()
	if strings.Contains(logOutput, "Dump HTTP2 Frame error") && strings.Contains(logOutput, "unexpected EOF") {
		t.Errorf("Display() should not log error for io.ErrUnexpectedEOF, got: %s", logOutput)
	}

	t.Logf("Display returned %d bytes for incomplete frame", len(result))
}
