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
	_, err := http.ReadResponse(buf, nil)
	if err != nil {
		return err
	}
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
	rawData, err := io.ReadAll(hr.response.Body)
	rawLength := int64(len(rawData))
	switch err {
	case nil:
		// Passed
	case io.ErrUnexpectedEOF:
		// If the server declared the Content-Length, Body is a LimitedReader
		// Raw data length smaller than "Content-Length" will cause UnexpectedEOF error
		// e.g. Head Method response with "Content-Length" header, raw data length is 0
		if rawLength > 0 && hr.response.ContentLength > rawLength {
			log.Println("[http response] Truncated response body")
		}
	default:
		log.Println("[http response] Read response body error:", err)
		return hr.reader.Bytes()
	}
	if hr.response.ContentLength < 0 {
		log.Println("[http response] Chunked response body")
	}
	var reader io.ReadCloser
	switch hr.response.Header.Get("Content-Encoding") {
	case "gzip":
		if rawLength == 0 {
			break
		}
		reader, err = gzip.NewReader(bytes.NewReader(rawData))
		if err != nil {
			log.Println("[http response] Create gzip reader error:", err)
			break
		}
		rawData, err = io.ReadAll(reader)
		if err != nil {
			log.Println("[http response] Uncompress gzip data error:", err)
			break
		}
		// gzip uncompressed success
		// hr.response.ContentLength = int64(len(raw))
		hr.packerType = PacketTypeGzip
		defer reader.Close()
	default:
		//reader = hr.response.Body
		hr.packerType = PacketTypeNull
		//TODO for debug
	}
	//	headerMap := bytes.NewBufferString("")
	//	for k, v := range hr.response.Header {
	//		headerMap.WriteString(fmt.Sprintf("\t%s\t=>\t%s\n", k, v))
	//	}
	b, err := httputil.DumpResponse(hr.response, false)
	if err != nil {
		log.Println("[http response] DumpResponse error:", err)
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
	hr := &HTTPResponse{}
	hr.Init()
	Register(hr)
}
