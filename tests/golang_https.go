package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func main() {

	b, e := GetHttp("https://baidu.com")
	if e == nil {
		fmt.Printf("response body: %s\n\n", b)
	} else {
		fmt.Printf("error :%v", e)
	}
}

func GetHttp(url string) (body []byte, err error) {
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "ecapture_go_master_secret.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, KeyLogWriter: f},
		}}
	resp, e := c.Get(url)
	if e != nil {
		return nil, e
	}

	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	return body, err
}
