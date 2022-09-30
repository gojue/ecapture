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
	packerType PACKET_TYPE
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

func (this *HTTPRequest) PacketType() PACKET_TYPE {
	return this.packerType
}

func (this *HTTPRequest) ParserType() PARSER_TYPE {
	return PARSER_TYPE_HTTP_REQUEST
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
