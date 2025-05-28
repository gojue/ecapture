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
	"errors"
	"io"
	"os"
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
