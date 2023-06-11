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

func (hr *HTTPResponse) Init() {
	hr.reader = bytes.NewBuffer(nil)
	hr.bufReader = bufio.NewReader(hr.reader)
	hr.receivedLen = 0
	hr.headerLength = 0
}

func (hr *HTTPResponse) Name() string {
	return "HTTPResponse"
}

func (hr *HTTPResponse) PacketType() PacketType {
	return hr.packerType
}

func (hr *HTTPResponse) ParserType() ParserType {
	return ParserTypeHttpResponse
}

func (hr *HTTPResponse) Write(b []byte) (int, error) {
	var l int
	var e error
	var req *http.Response
	// 如果未初始化
	if !hr.isInit {
		l, e = hr.reader.Write(b)
		if e != nil {
			return l, e
		}
		req, e = http.ReadResponse(hr.bufReader, nil)

		if e != nil {
			return 0, e
		}

		hr.response = req
		hr.isInit = true
	} else {
		// 如果已初始化
		l, e = hr.reader.Write(b)
		if e != nil {
			return 0, e
		}
	}
	hr.receivedLen += int64(l)

	// 检测是否接收完整个包
	//if hr.response.ContentLength >= hr.receivedLen {
	if false {
		hr.isDone = true
	}

	return l, nil
}

func (hr *HTTPResponse) detect(payload []byte) error {
	rd := bytes.NewReader(payload)
	buf := bufio.NewReader(rd)
	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		return err
	}
	hr.response = res
	return nil
}

func (hr *HTTPResponse) IsDone() bool {
	return hr.isDone
}

func (hr *HTTPResponse) Reset() {
	hr.isDone = false
	hr.isInit = false
	hr.reader.Reset()
	hr.bufReader.Reset(hr.reader)
}

func (hr *HTTPResponse) Display() []byte {
	var reader io.ReadCloser
	var err error
	switch hr.response.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(hr.response.Body)
		if err != nil {
			log.Println(err)
			break
		}

		// gzip uncompressed success
		hr.response.Body = reader
		hr.packerType = PacketTypeGzip
		defer reader.Close()
	default:
		//reader = hr.response.Body
		hr.packerType = PacketTypeNull
		//TODO for debug
		//return []byte("")
	}
	headerMap := bytes.NewBufferString("")
	for k, v := range hr.response.Header {
		headerMap.WriteString(fmt.Sprintf("\t%s\t=>\t%s\n", k, v))
	}
	//log.Printf("HTTPS Headers \n\t%s", headerMap.String())

	var b []byte
	var e error

	if hr.response.ContentLength == 0 {
		b, e = httputil.DumpResponse(hr.response, false)
	} else {
		b, e = httputil.DumpResponse(hr.response, true)
	}
	if e != nil {
		log.Println("[http response] DumpResponse error:", e)
		return hr.reader.Bytes()
	}
	return b
}

func init() {
	hr := &HTTPResponse{}
	hr.Init()
	Register(hr)
}
