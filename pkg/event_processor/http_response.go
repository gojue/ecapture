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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
)

// length of \r\n\r\n
const HTTP_NEW_LINE_LENGTH = 4

type HTTPResponse struct {
	response     *http.Response
	packerType   PacketType
	isDone       bool
	receivedLen  int64
	headerLength int64
	isInit       bool
	reader       *bytes.Buffer
	bufReader    *bufio.Reader
}

func (this *HTTPResponse) Init() {
	this.reader = bytes.NewBuffer(nil)
	this.bufReader = bufio.NewReader(this.reader)
	this.receivedLen = 0
	this.headerLength = 0
}

func (this *HTTPResponse) Name() string {
	return "HTTPResponse"
}

func (this *HTTPResponse) PacketType() PacketType {
	return this.packerType
}

func (this *HTTPResponse) ParserType() ParserType {
	return ParserTypeHttpResponse
}

func (this *HTTPResponse) Write(b []byte) (int, error) {
	var l int
	var e error
	var req *http.Response
	// 如果未初始化
	if !this.isInit {
		l, e = this.reader.Write(b)
		if e != nil {
			return l, e
		}
		req, e = http.ReadResponse(this.bufReader, nil)

		if e != nil {
			return 0, e
		}

		this.response = req
		this.isInit = true
	} else {
		// 如果已初始化
		l, e = this.reader.Write(b)
		if e != nil {
			return 0, e
		}
	}
	this.receivedLen += int64(l)

	// 检测是否接收完整个包
	//if this.response.ContentLength >= this.receivedLen {
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
		this.packerType = PacketTypeGzip
		defer reader.Close()
	default:
		//reader = this.response.Body
		this.packerType = PacketTypeNull
		//log.Println("not gzip content")
		//TODO for debug
		//return []byte("")
	}
	headerMap := bytes.NewBufferString("")
	for k, v := range this.response.Header {
		headerMap.WriteString(fmt.Sprintf("\t%s\t=>\t%s\n", k, v))
	}
	log.Printf("HTTPS Headers \n\t%s", headerMap.String())

	var b []byte
	var e error

	if this.response.ContentLength == 0 {
		b, e = httputil.DumpResponse(this.response, false)
	} else {
		b, e = httputil.DumpResponse(this.response, true)
	}
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
