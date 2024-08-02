// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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
	"testing"
)

func TestHttpResponseParser(t *testing.T) {

	httpBody := []byte(`HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: private, no-cache, no-store, proxy-revalidate, no-transform
Connection: keep-alive
Content-Length: 2443
Content-Type: text/html
Date: Fri, 10 May 2024 03:54:10 GMT
Etag: "58860401-98b"
Last-Modified: Mon, 23 Jan 2017 13:24:17 GMT
Pragma: no-cache
Server: bfe/1.0.8.18
Set-Cookie: BDORZ=27315; max-age=86400; domain=.baidu.com; path=/

`)

	hr := &HTTPResponse{}
	hr.Init()
	err := hr.detect(httpBody)
	if err != nil {
		t.Errorf("detect http response failed: %v", err)
	}
	i, e := hr.Write(httpBody)
	if e != nil {
		t.Errorf("write http response failed: %v", e)
	}
	t.Logf("wrot:%d", i)
	if hr.response.Proto != "HTTP/1.1" {
		t.Fatalf("TestHttpResponseParser: http response proto error, want: HTTP/1.1, got:%s", hr.response.Proto)
	}
	//t.Logf("http reponse body :%s", hr.Display())

}
