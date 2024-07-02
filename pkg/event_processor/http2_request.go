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
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const H2Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const H2MagicLen = len(H2Magic)

type HTTP2Request struct {
	framer     *http2.Framer
	packerType PacketType
	isDone     bool
	isInit     bool
	reader     *bytes.Buffer
	bufReader  *bufio.Reader
}

func (h2r *HTTP2Request) detect(payload []byte) error {
	data := string(payload[0:H2MagicLen])
	if data != H2Magic {
		return errors.New("Not Match http2 Magic")
	}
	return nil
}

func (h2r *HTTP2Request) Init() {
	h2r.reader = bytes.NewBuffer(nil)
	h2r.bufReader = bufio.NewReader(h2r.reader)
	h2r.framer = http2.NewFramer(nil, h2r.bufReader)
	h2r.framer.ReadMetaHeaders = hpack.NewDecoder(0, nil)
}

func (h2r *HTTP2Request) Write(b []byte) (int, error) {
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

func (h2r *HTTP2Request) ParserType() ParserType {
	return ParserTypeHttp2Request
}

func (h2r *HTTP2Request) PacketType() PacketType {
	return h2r.packerType
}

func (h2r *HTTP2Request) Name() string {
	return "HTTP2Request"
}

func (h2r *HTTP2Request) IsDone() bool {
	return h2r.isDone
}

func (h2r *HTTP2Request) Display() []byte {
	h2r.bufReader.Discard(H2MagicLen)
	bufStr := bytes.NewBufferString("")
	for {
		f, err := h2r.framer.ReadFrame()
		if err != nil {
			if err != io.EOF {
				log.Println("[HTTP2Request] Dump HTTP2 Frame error:", err)
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
	h2r := &HTTP2Request{}
	h2r.Init()
	Register(h2r)
}

func (h2r *HTTP2Request) Reset() {
	h2r.isDone = false
	h2r.isInit = false
	h2r.reader.Reset()
	h2r.bufReader.Reset(h2r.reader)
}
