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

func (this *HTTPRequest) Init() {
	this.reader = bytes.NewBuffer(nil)
	this.bufReader = bufio.NewReader(this.reader)
}

func (this *HTTPRequest) Name() string {
	return "HTTPRequest"
}

func (this *HTTPRequest) PacketType() PacketType {
	return this.packerType
}

func (this *HTTPRequest) ParserType() ParserType {
	return ParserTypeHttpRequest
}

func (this *HTTPRequest) Write(b []byte) (int, error) {
	// 如果未初始化
	if !this.isInit {
		n, e := this.reader.Write(b)
		if e != nil {
			return n, e
		}
		req, err := http.ReadRequest(this.bufReader)
		if err != nil {
			return 0, err
		}
		this.request = req
		this.isInit = true
		return n, nil
	}

	// 如果已初始化
	l, e := this.reader.Write(b)
	if e != nil {
		return 0, e
	}

	// TODO 检测是否接收完整个包
	if false {
		this.isDone = true
	}

	return l, nil
}

func (this *HTTPRequest) detect(payload []byte) error {
	//this.Init()
	rd := bytes.NewReader(payload)
	buf := bufio.NewReader(rd)
	req, err := http.ReadRequest(buf)
	if err != nil {
		return err
	}
	this.request = req
	return nil
}

func (this *HTTPRequest) IsDone() bool {
	return this.isDone
}

func (this *HTTPRequest) Reset() {
	this.isDone = false
	this.isInit = false
	this.reader.Reset()
	this.bufReader.Reset(this.reader)
}

func (this *HTTPRequest) Display() []byte {
	if this.request.Proto == "HTTP/2.0" {
		return this.reader.Bytes()
	}
	b, e := httputil.DumpRequest(this.request, true)
	if e != nil {
		log.Println("DumpRequest error:", e)
		return nil
	}
	return b
}

func init() {
	hr := &HTTPRequest{}
	hr.Init()
	Register(hr)
}
