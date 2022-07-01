package event_processor

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
)

func readHTTPResponse(payload []byte) (*http.Response, error) {
	rd := bytes.NewReader(payload)
	buf := bufio.NewReader(rd)
	rep := new(http.Request)
	resp, err := http.ReadResponse(buf, rep)
	if err != nil {
		return nil, err
	}

	//save response body
	b := new(bytes.Buffer)
	io.Copy(b, resp.Body)
	resp.Body.Close()
	resp.Body = ioutil.NopCloser(b)
	return resp, nil
}
