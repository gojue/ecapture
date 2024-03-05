package event_processor

import (
	"ecapture/user/event"
	"strings"

	"golang.org/x/sys/unix"
)

// 特殊处理bashevent
type bashEventWorker struct {
	incoming  chan event.IEventStruct
	status    ProcessStatus
	UUID      string
	processor *EventProcessor
	line      string
	retVal    uint32
}

func NewBashEventWorker(uuid string, processor *EventProcessor) IWorker {
	beWorker := &bashEventWorker{}
	beWorker.init(uuid, processor)
	go func() {
		beWorker.Run()
	}()
	return beWorker
}

func (ew *bashEventWorker) init(uuid string, processor *EventProcessor) {
	ew.incoming = make(chan event.IEventStruct)
	ew.status = ProcessStateInit
	ew.UUID = uuid
	ew.processor = processor
}

func (bew *bashEventWorker) GetUUID() string {
	return bew.UUID
}

func (bew *bashEventWorker) Write(e event.IEventStruct) error {
	bew.incoming <- e
	return nil
}

func (bew *bashEventWorker) Run() {
	for e := range bew.incoming {
		bashEvent, _ := e.(*event.BashEvent)
		line := strings.TrimSpace(unix.ByteSliceToString((bashEvent.Line[:])))
		if (line == "" || line == "\\") && bew.status == ProcessStateInit {
			continue
		}
		bew.line += line
		bew.status = ProcessStateProcessing
		if bashEvent.Type == 1 {
			//retval
			bew.retVal = bashEvent.Retval
			bew.Close()
			return
		}

		if strings.HasPrefix(line, "exit") || strings.HasPrefix(line, "exec") {
			//无返回值的命令
			bew.Close()
			return
		}
		bew.line += "\n"
	}
}

func (bew *bashEventWorker) Close() {
	bew.status = ProcessStateDone
	bew.Display()
	bew.processor.delWorkerByUUID(bew)
}

// 输出整个Command内容
func (bew *bashEventWorker) Display() {
	bew.processor.GetLogger().Printf("pid_uid_comm:%s, length:%d, retVal:%v\nline:%v", bew.UUID, len(bew.line), bew.retVal, bew.line)
}
