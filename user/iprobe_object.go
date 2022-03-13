package user

import (
	"github.com/cilium/ebpf"
)

type IEBPFProbeObject interface {
	// Close 关闭对象
	Close() error

	// Events 获取事件列表
	Events() []*ebpf.Map

	DecodeFun(p *ebpf.Map) (IEventStruct, bool)

	initDecodeFun()

	EventsDecode([]byte, IEventStruct) (s string, err error)
}

type EBPFProbeObject struct {
	eventFuncMap map[*ebpf.Map]IEventStruct
}

func (t *EBPFProbeObject) initDecodeFun() {
	panic("e.EBPFProbeObject.DecodeFun not implemented yet")
}

func (e *EBPFProbeObject) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := e.eventFuncMap[em]
	return fun, found
}

func (e *EBPFProbeObject) EventsDecode(payload []byte, es IEventStruct) (s string, err error) {
	te := es.Clone()
	err = te.Decode(payload)
	if err != nil {
		return
	}
	s = te.String()
	return
}
