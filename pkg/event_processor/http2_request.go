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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const ClientPrefaceLen = len(http2.ClientPreface)

type HTTP2Request struct {
	framer     *http2.Framer
	packerType PacketType
	isDone     bool
	isInit     bool
	reader     *bytes.Buffer
	bufReader  *bufio.Reader
}

func (h2r *HTTP2Request) detect(payload []byte) error {
	payloadLen := len(payload)
	if payloadLen < ClientPrefaceLen {
		return errors.New("payload less than http2 ClientPreface")
	}
	data := string(payload[0:ClientPrefaceLen])
	if data != http2.ClientPreface {
		return errors.New("not match http2 ClientPreface")
	}
	return nil
}

func (h2r *HTTP2Request) Init() {
	h2r.reader = bytes.NewBuffer(nil)
	h2r.bufReader = bufio.NewReader(h2r.reader)
	h2r.framer = http2.NewFramer(nil, h2r.bufReader)
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
	_, err := h2r.bufReader.Discard(ClientPrefaceLen)
	if err != nil {
		log.Println("[http2 request] Discard HTTP2 Magic error:", err)
		return h2r.reader.Bytes()
	}
	encodingMap := make(map[uint32]string)
	dataBufMap := make(map[uint32]*bytes.Buffer)
	frameBuf := bytes.NewBufferString("")
	hdec := hpack.NewDecoder(4096, nil)
	for {
		f, err := h2r.framer.ReadFrame()
		if err != nil {
			if err != io.EOF {
				log.Println("[http2 request] Dump HTTP2 Frame error:", err)
			}
			break
		}
		switch f := f.(type) {
		case *http2.HeadersFrame:
			streamID := f.StreamID
			frameBuf.WriteString(fmt.Sprintf("\nFrame Type\t=>\tHEADERS\nFrame StreamID\t=>\t%d\nFrame Length\t=>\t%d\n", streamID, f.Length))
			if f.HeadersEnded() {
				fields, err := hdec.DecodeFull(f.HeaderBlockFragment())
				for _, header := range fields {
					frameBuf.WriteString(fmt.Sprintf("%s\n", header.String()))
					if header.Name == "content-encoding" {
						encodingMap[streamID] = header.Value
					}
				}
				if err != nil {
					frameBuf.WriteString("Incorrect HPACK context, Please use PCAP mode to get correct header fields ...\n")
				}
			} else {
				frameBuf.WriteString("Not Supported HEADERS Frame with CONTINUATION frames\n")
			}
		case *http2.DataFrame:
			streamID := f.StreamID
			frameBuf.WriteString(fmt.Sprintf("\nFrame Type\t=>\tDATA\nFrame StreamID\t=>\t%d\nFrame Length\t=>\t%d\n", streamID, f.Length))
			payload := f.Data()
			switch encodingMap[streamID] {
			case "gzip":
				h2r.packerType = PacketTypeGzip
				frameBuf.WriteString("Partial entity body with gzip encoding ... \n")
				if dataBufMap[streamID] == nil {
					dataBufMap[streamID] = bytes.NewBuffer(nil)
				}
				_, err := dataBufMap[streamID].Write(payload)
				if err != nil {
					log.Println("[http2 request] Write HTTP2 Data Frame buffuer error:", err)
				}
			default:
				h2r.packerType = PacketTypeNull
				frameBuf.Write(payload)
				frameBuf.WriteString("\n")
			}
		default:
			fh := f.Header()
			frameBuf.WriteString(fmt.Sprintf("\nFrame Type\t=>\t%s\nFrame StreamID\t=>\t%d\n", fh.Type.String(), fh.StreamID))
		}
	}
	// merge data frame with encoding
	for id, buf := range dataBufMap {
		if buf.Len() > 0 && encodingMap[id] == "gzip" {
			payload := buf.Bytes()
			reader, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				log.Println("[http2 request] Create gzip reader error:", err)
				continue
			}
			defer func() { _ = reader.Close() }()
			payload, err = io.ReadAll(reader)
			if err != nil {
				log.Println("[http2 request] Uncompress gzip data error:", err)
				continue
			}
			frameBuf.WriteString(fmt.Sprintf("\nMerged Data Frame, StreamID\t=>\t%d\nMerged Data Frame, Final Length\t=>\t%d\n\n", id, len(payload)))
			frameBuf.Write(payload)
			frameBuf.WriteString("\n")
		}
	}
	return frameBuf.Bytes()
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
