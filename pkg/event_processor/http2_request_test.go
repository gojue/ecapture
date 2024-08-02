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
	"golang.org/x/net/http2"
	"io"
	"os"
	"testing"
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
		t.Fatalf("TestHttp2RequestParser: detect http request failed: %v", err)
	}
	i, e := h2r.Write(httpBody)
	if e != nil {
		t.Errorf("TestHttp2RequestParser: write http request failed: %v", e)
	}
	t.Logf("TestHttp2RequestParser: wrot body:%d", i)

	_, err = h2r.bufReader.Discard(H2MagicLen)
	if err != nil {
		t.Logf("[http2 request] Discard HTTP2 Magic error:%v", err)
	}
	var frameTypes = make([]string, 0)
	for {
		f, err := h2r.framer.ReadFrame()
		if err != nil {
			if err != io.EOF {
				t.Fatalf("[http2 response] read http2 response frame error:%v", err)
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
