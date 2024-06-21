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

package event_processor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
)

type HTTPRequest struct {
	request    *http.Request
	packerType PacketType
	isDone     bool
	isInit     bool
	reader     *bytes.Buffer
	bufReader  *bufio.Reader
}

func (hr *HTTPRequest) Init() {
	hr.reader = bytes.NewBuffer(nil)
	hr.bufReader = bufio.NewReader(hr.reader)
}

func (hr *HTTPRequest) Name() string {
	return "HTTPRequest"
}

func (hr *HTTPRequest) PacketType() PacketType {
	return hr.packerType
}

func (hr *HTTPRequest) ParserType() ParserType {
	return ParserTypeHttpRequest
}

func (hr *HTTPRequest) Write(b []byte) (int, error) {
	// 如果未初始化
	if !hr.isInit {
		n, e := hr.reader.Write(b)
		if e != nil {
			return n, e
		}
		req, err := http.ReadRequest(hr.bufReader)
		if err != nil {
			return 0, err
		}
		hr.request = req
		hr.isInit = true
		return n, nil
	}

	// 如果已初始化
	l, e := hr.reader.Write(b)
	if e != nil {
		return 0, e
	}
	// TODO 检测是否接收完整个包
	if false {
		hr.isDone = true
	}

	return l, nil
}

func (hr *HTTPRequest) detect(payload []byte) error {
	//hr.Init()
	rd := bytes.NewReader(payload)
	buf := bufio.NewReader(rd)
	_, err := http.ReadRequest(buf)
	if err != nil {
		return err
	}
	return nil
}

func (hr *HTTPRequest) IsDone() bool {
	return hr.isDone
}

func (hr *HTTPRequest) Reset() {
	hr.isDone = false
	hr.isInit = false
	hr.reader.Reset()
	hr.bufReader.Reset(hr.reader)
}

func (hr *HTTPRequest) Display() []byte {
	if hr.request.Proto == "HTTP/2.0" {
		return hr.reader.Bytes()
	}
	rawData, err := io.ReadAll(hr.request.Body)
	rawLength := int64(len(rawData))
	switch err {
	case nil:
		// Passed
	case io.ErrUnexpectedEOF:
		if rawLength > 0 && hr.request.ContentLength > rawLength {
			log.Println("[http request] Truncated request body")
		}
	default:
		log.Println("[http request] Read request body error:", err)
		return hr.reader.Bytes()
	}
	var reader io.ReadCloser
	switch hr.request.Header.Get("Content-Encoding") {
	case "gzip":
		if rawLength == 0 {
			break
		}
		reader, err = gzip.NewReader(bytes.NewReader(rawData))
		if err != nil {
			log.Println("[http request] Create gzip reader error:", err)
			break
		}
		rawData, err = io.ReadAll(reader)
		if err != nil {
			log.Println("[http request] Uncompress gzip data error:", err)
			break
		}
		// gzip uncompressed success
		// hr.request.Body = io.NopCloser(bytes.NewReader(gbuf))
		// hr.request.ContentLength = int64(len(gbuf))
		hr.packerType = PacketTypeGzip
		defer reader.Close()
	default:
		hr.packerType = PacketTypeNull
	}
	b, err := httputil.DumpRequest(hr.request, false)
	if err != nil {
		log.Println("[http request] DumpRequest error:", err)
		return hr.reader.Bytes()
	}
	var buff bytes.Buffer
	buff.Write(b)
	if rawLength > 0 {
		buff.Write(rawData)
	}
	return buff.Bytes()
}

func init() {
	hr := &HTTPRequest{}
	hr.Init()
	Register(hr)
}
