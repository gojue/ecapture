package event_processor

import (
	"ecapture/user/event"
	"encoding/hex"
	"time"
)

type IWorker interface {

	// 定时器1 ，定时判断没有后续包，则解析输出

	// 定时器2， 定时判断没后续包，则通知上层销毁自己

	// 收包
	Write(event.IEventStruct) error
	GetUUID() string
}

const (
	MAX_TICKER_COUNT = 10 // 1 Sencond/(eventWorker.ticker.C) = 10
	MAX_CHAN_LEN     = 16 // 包队列长度
	//MAX_EVENT_LEN    = 16 // 事件数组长度
)

type eventWorker struct {
	incoming chan event.IEventStruct
	//events      []user.IEventStruct
	status      PROCESS_STATUS
	packetType  PACKET_TYPE
	ticker      *time.Ticker
	tickerCount uint8
	UUID        string
	processor   *EventProcessor
	parser      IParser
}

func NewEventWorker(uuid string, processor *EventProcessor) IWorker {
	eWorker := &eventWorker{}
	eWorker.init(uuid, processor)
	go func() {
		eWorker.Run()
	}()
	return eWorker
}

func (this *eventWorker) init(uuid string, processor *EventProcessor) {
	this.ticker = time.NewTicker(time.Millisecond * 100)
	this.incoming = make(chan event.IEventStruct, MAX_CHAN_LEN)
	this.status = PROCESS_STATE_INIT
	this.UUID = uuid
	this.processor = processor
}

func (this *eventWorker) GetUUID() string {
	return this.UUID
}

func (this *eventWorker) Write(e event.IEventStruct) error {
	this.incoming <- e
	return nil
}

// 输出包内容
func (this *eventWorker) Display() {
	// 解析器类型检测
	if this.parser.ParserType() != PARSER_TYPE_HTTP_RESPONSE {
		//临时调试开关
		//return
	}

	//  输出包内容
	b := this.parser.Display()

	if len(b) <= 0 {
		return
	}

	if this.processor.isHex {
		b = []byte(hex.Dump(b))
	}

	// TODO 格式化的终端输出
	// 重置状态
	this.processor.GetLogger().Printf("UUID:%s, Name:%s, Type:%d, Length:%d", this.UUID, this.parser.Name(), this.parser.ParserType(), len(b))
	this.processor.GetLogger().Println("\n" + string(b))
	this.parser.Reset()
	// 设定状态、重置包类型
	this.status = PROCESS_STATE_DONE
	this.packetType = PACKET_TYPE_NULL
}

// 解析类型，输出
func (this *eventWorker) parserEvent(e event.IEventStruct) {
	if this.status == PROCESS_STATE_INIT {
		// 识别包类型，只检测，不把payload设置到parser的属性中，需要重新调用parser.Write()写入
		parser := NewParser(e.Payload())
		this.parser = parser
	}

	// 设定当前worker的状态为正在解析
	this.status = PROCESS_STATE_PROCESSING

	// 写入payload到parser
	_, err := this.parser.Write(e.Payload()[:e.PayloadLen()])
	if err != nil {
		this.processor.GetLogger().Fatalf("eventWorker: detect packet type error, UUID:%s, error:%v", this.UUID, err)
	}

	// 是否接收完成，能否输出
	if this.parser.IsDone() {
		this.Display()
	}
}

func (this *eventWorker) Run() {
	for {
		select {
		case _ = <-this.ticker.C:
			// 输出包
			if this.tickerCount > MAX_TICKER_COUNT {
				this.Close()
				return
			}
			this.tickerCount++
		case e := <-this.incoming:
			// reset tickerCount
			this.tickerCount = 0
			this.parserEvent(e)
		}
	}

}

func (this *eventWorker) Close() {
	// 即将关闭， 必须输出结果
	this.Display()
	this.tickerCount = 0
	this.processor.delWorkerByUUID(this)
}
