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

type HTTPResponse struct {
	response   *http.Response
	packerType PACKET_TYPE
	isDone     bool
	isInit     bool
	reader     *bytes.Buffer
	bufReader  *bufio.Reader
}

func (this *HTTPResponse) Init() {
	this.reader = bytes.NewBuffer(nil)
	this.bufReader = bufio.NewReader(this.reader)
}

func (this *HTTPResponse) Name() string {
	return "HTTPResponse"
}

func (this *HTTPResponse) PacketType() PACKET_TYPE {
	return this.packerType
}

func (this *HTTPResponse) ParserType() PARSER_TYPE {
	return PARSER_TYPE_HTTP_RESPONSE
}

func (this *HTTPResponse) Write(b []byte) (int, error) {
	// 如果未初始化
	if !this.isInit {
		n, e := this.reader.Write(b)
		if e != nil {
			return n, e
		}
		req, err := http.ReadResponse(this.bufReader, nil)
		if err != nil {
			return 0, err
		}
		this.response = req
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

func (this *HTTPResponse) detect(payload []byte) error {
	rd := bytes.NewReader(payload)
	buf := bufio.NewReader(rd)
	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		return err
	}
	this.response = res
	return nil
}

func (this *HTTPResponse) IsDone() bool {
	return this.isDone
}

func (this *HTTPResponse) Reset() {
	this.isDone = false
	this.isInit = false
	this.reader.Reset()
	this.bufReader.Reset(this.reader)
}

func (this *HTTPResponse) Display() []byte {
	var reader io.ReadCloser
	var err error
	switch this.response.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(this.response.Body)
		if err != nil {
			log.Println(err)
			break
		}

		// gzip uncompressed success
		this.response.Body = reader
		this.packerType = PACKET_TYPE_GZIP
		defer reader.Close()
	default:
		//reader = this.response.Body
		this.packerType = PACKET_TYPE_NULL
		//TODO for debug
		//return []byte("")
	}

	b, e := httputil.DumpResponse(this.response, true)
	if e != nil {
		log.Println("DumpResponse error:", e)
		return []byte("")
	}
	return b
}

func init() {
	hr := &HTTPResponse{}
	hr.Init()
	Register(hr)
}
