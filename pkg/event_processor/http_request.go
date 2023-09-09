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
	req, err := http.ReadRequest(buf)
	if err != nil {
		return err
	}
	hr.request = req
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
	b, e := httputil.DumpRequest(hr.request, true)
	if e != nil {
		log.Println("DumpRequest error:", e)
		return hr.reader.Bytes()
	}
	return b
}

func init() {
	hr := &HTTPRequest{}
	hr.Init()
	Register(hr)
}
