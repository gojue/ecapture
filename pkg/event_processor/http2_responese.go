// Copyright 2024 yuweizzz <yuwei764969238@gmail.com>. All Rights Reserved.
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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type HTTP2Response struct {
	framer     *http2.Framer
	packerType PacketType
	isDone     bool
	isInit     bool
	reader     *bytes.Buffer
	bufReader  *bufio.Reader
}

func (h2r *HTTP2Response) detect(payload []byte) error {
	rd := bytes.NewReader(payload)
	buf := bufio.NewReader(rd)
	framer := http2.NewFramer(nil, buf)
	framer.ReadMetaHeaders = hpack.NewDecoder(0, nil)
	_, err := framer.ReadFrame()
	if err != nil {
		return err
	}
	return nil
}

func (h2r *HTTP2Response) Init() {
	h2r.reader = bytes.NewBuffer(nil)
	h2r.bufReader = bufio.NewReader(h2r.reader)
	h2r.framer = http2.NewFramer(nil, h2r.bufReader)
	h2r.framer.ReadMetaHeaders = hpack.NewDecoder(0, nil)
}

func (h2r *HTTP2Response) Write(b []byte) (int, error) {
	if !h2r.isInit {
		h2r.Init()
		h2r.isInit = true
	}
	length, err := h2r.reader.Write(b)
	if err != nil {
		return 0, err
	}
	return length, nil
}

func (h2r *HTTP2Response) ParserType() ParserType {
	return ParserTypeHttp2Response
}

func (h2r *HTTP2Response) PacketType() PacketType {
	return h2r.packerType
}

func (h2r *HTTP2Response) Name() string {
	return "HTTP2Response"
}

func (h2r *HTTP2Response) IsDone() bool {
	return h2r.isDone
}

func (h2r *HTTP2Response) Display() []byte {
	bufStr := bytes.NewBufferString("")
	for {
		f, err := h2r.framer.ReadFrame()
		if err != nil {
			if err != io.EOF {
				log.Println("[HTTP2Response] Dump HTTP2 Frame error:", err)
			}
			break
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			bufStr.WriteString(fmt.Sprintf("\nFrame Type\t=>\tHEADERS\n"))
			for _, header := range f.Fields {
				bufStr.WriteString(fmt.Sprintf("%s\n", header.String()))
			}
		case *http2.DataFrame:
			bufStr.WriteString(fmt.Sprintf("\nFrame Type\t=>\tDATA\n"))
			payload := f.Data()
			bufStr.Write(payload)
		default:
			fh := f.Header()
			bufStr.WriteString(fmt.Sprintf("\nFrame Type\t=>\t%s\n", fh.Type.String()))
		}
	}
	return bufStr.Bytes()
}

func init() {
	h2r := &HTTP2Response{}
	h2r.Init()
	Register(h2r)
}

func (h2r *HTTP2Response) Reset() {
	h2r.isDone = false
	h2r.isInit = false
	h2r.reader.Reset()
	h2r.bufReader.Reset(h2r.reader)
}
