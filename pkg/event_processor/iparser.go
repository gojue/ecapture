package event_processor

import (
	"bytes"
	"fmt"
)

type PROCESS_STATUS uint8
type PACKET_TYPE uint8
type PARSER_TYPE uint8

const (
	PROCESS_STATE_INIT PROCESS_STATUS = iota
	PROCESS_STATE_PROCESSING
	PROCESS_STATE_DONE
)

const (
	PACKET_TYPE_NULL PACKET_TYPE = iota
	PACKET_TYPE_UNKNOW
	PACKET_TYPE_GZIP
	PACKET_TYPE_WEB_SOCKET
)

const (
	PARSER_TYPE_NULL PARSER_TYPE = iota
	PARSER_TYPE_HTTP_REQUEST
	PARSER_TYPE_HTTP_RESPONSE
	PARSER_TYPE_WEB_SOCKET
)

type IParser interface {
	detect(b []byte) error
	Write(b []byte) (int, error)
	ParserType() PARSER_TYPE
	PacketType() PACKET_TYPE
	//Body() []byte
	Name() string
	IsDone() bool
	Init()
	Display() []byte
	Reset()
}

var parsers = make(map[string]IParser)

func Register(p IParser) {
	if p == nil {
		panic("Register Parser is nil")
	}
	name := p.Name()
	if _, dup := parsers[name]; dup {
		panic(fmt.Sprintf("Register called twice for Parser %s", name))
	}
	parsers[name] = p
}

// GetModules 获取modules列表
func GetAllModules() map[string]IParser {
	return parsers
}

// GetModules 获取modules列表
func GetModuleByName(name string) IParser {
	return parsers[name]
}

func NewParser(payload []byte) IParser {
	if len(payload) > 0 {
		for _, parser := range GetAllModules() {
			err := parser.detect(payload)
			if err == nil {
				var newParser IParser
				switch parser.ParserType() {
				case PARSER_TYPE_NULL:
					newParser = new(DefaultParser)
				case PARSER_TYPE_HTTP_REQUEST:
					newParser = new(HTTPRequest)
				case PARSER_TYPE_HTTP_RESPONSE:
					newParser = new(HTTPResponse)
				}
				newParser.Init()
				return newParser
			}
		}
	}
	var np = &DefaultParser{}
	np.reader = bytes.NewBuffer(nil)
	return np
}

type DefaultParser struct {
	reader *bytes.Buffer
	isdone bool
}

func (this *DefaultParser) ParserType() PARSER_TYPE {
	return PARSER_TYPE_NULL
}

func (this *DefaultParser) PacketType() PACKET_TYPE {
	return PACKET_TYPE_NULL
}

func (this *DefaultParser) Write(b []byte) (int, error) {
	this.isdone = true
	return this.reader.Write(b)
}

// DefaultParser 检测包类型
func (this *DefaultParser) detect(b []byte) error {
	return nil
}

func (this *DefaultParser) Name() string {
	return "DefaultParser"
}

func (this *DefaultParser) IsDone() bool {
	return this.isdone
}

func (this *DefaultParser) Init() {

}

func (this *DefaultParser) Display() []byte {
	return []byte(CToGoString(this.reader.Bytes()))
}

func (this *DefaultParser) Reset() {
	this.isdone = false
	this.reader.Reset()
}
