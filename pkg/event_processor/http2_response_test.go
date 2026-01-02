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

func TestHttp2ResponseParser(t *testing.T) {
	h2ResponseFile := "testdata/952293616935739.bin"
	httpBody, err := os.ReadFile(h2ResponseFile)
	if err != nil {
		t.Fatalf("TestHttp2ResponseParser: read payload file error: %s, file:%s", err.Error(), h2ResponseFile)
	}

	h2r := &HTTP2Response{}
	h2r.Init()
	err = h2r.detect(httpBody)
	if err != nil {
		t.Fatalf("TestHttp2ResponseParser: detect http response failed: %s", err.Error())
	}
	i, err := h2r.Write(httpBody)
	if err != nil {
		t.Errorf("TestHttp2ResponseParser: write http response failed: %s", err.Error())
	}
	t.Logf("TestHttp2ResponseParser: wrot body:%d", i)

	var frameTypes = make([]string, 0)
	// for
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
			t.Logf("TestHttp2ResponseParser: frame type:%s", f.Type)
			frameTypes = append(frameTypes, f.Type.String())
		case *http2.DataFrame:
			t.Logf("TestHttp2ResponseParser: frame type:%s", f.Type)
			frameTypes = append(frameTypes, f.Type.String())
		default:
			fh := f.Header()
			frameTypes = append(frameTypes, fh.Type.String())
			t.Logf("TestHttp2ResponseParser: Frame Type\t=>\t%s", fh.Type.String())
		}
	}
	t.Logf("frameTypes:%v", frameTypes)
	if len(frameTypes) != 5 {
		t.Fatalf("TestHttp2ResponseParser: frameTypes length error, want: 5, got:%d", len(frameTypes))
	}
	_ = h2r.Display()
	//t.Logf("TestHttp2ResponseParser: http reponse body :%s", textBody)
}

// TestHttp2ResponseDisplayWithIncompleteFrame tests that Display() handles incomplete frames
// gracefully without logging errors. This simulates the scenario described in the issue where
// truncated TLS data causes io.ErrUnexpectedEOF during streaming capture.
func TestHttp2ResponseDisplayWithIncompleteFrame(t *testing.T) {
	h2ResponseFile := "testdata/952293616935739.bin"
	httpBody, err := os.ReadFile(h2ResponseFile)
	if err != nil {
		t.Fatalf("read payload file error: %s, file:%s", err.Error(), h2ResponseFile)
	}

	// Truncate the data to simulate incomplete frame (cut in the middle of a frame)
	// The test data has multiple frames, we'll cut it to leave an incomplete frame
	truncatedData := httpBody[:len(httpBody)/2]

	h2r := &HTTP2Response{}
	h2r.Init()

	// Verify truncated data can still be detected as HTTP2
	err = h2r.detect(truncatedData)
	if err != nil {
		t.Fatalf("detect http response failed: %s", err.Error())
	}

	_, err = h2r.Write(truncatedData)
	if err != nil {
		t.Fatalf("write http response failed: %s", err.Error())
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

// TestHttp2ResponseDisplayWithMinimalIncompleteFrame tests Display() with data that has
// a valid frame header but incomplete payload, which triggers io.ErrUnexpectedEOF.
func TestHttp2ResponseDisplayWithMinimalIncompleteFrame(t *testing.T) {
	// Create a minimal HTTP2 frame header that declares more data than available
	// Frame header: Length (3 bytes) + Type (1 byte) + Flags (1 byte) + Stream ID (4 bytes) = 9 bytes
	// We'll create a SETTINGS frame (type 0x04) that claims to have 18 bytes (0x12 hex) payload
	// but only provide the header without the payload data
	incompleteFrame := []byte{
		0x00, 0x00, 0x12, // Length: 18 bytes (0x12 hex) - payload not provided
		0x04,                   // Type: SETTINGS
		0x00,                   // Flags: none
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		// Missing payload - this will cause io.ErrUnexpectedEOF
	}

	h2r := &HTTP2Response{}
	h2r.Init()

	// Verify that our test data passes detection (valid frame header)
	err := h2r.detect(incompleteFrame)
	if err != nil {
		t.Fatalf("detect should pass for valid frame header: %s", err.Error())
	}

	_, err = h2r.Write(incompleteFrame)
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
