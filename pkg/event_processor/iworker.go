package event_processor

import (
	"ecapture/user"
	"time"
)

type IWorker interface {

	// 定时器1 ，定时判断没有后续包，则解析输出

	// 定时器2， 定时判断没后续包，则通知上层销毁自己

	// 收包
	Write(event user.IEventStruct) error
}

type PROCESS_STATUS uint8
type PACKET_TYPE uint8

const (
	PROCESS_STATE_ING PROCESS_STATUS = iota
	PROCESS_STATE_DONE
)

const (
	PACKET_TYPE_UNKNOW PACKET_TYPE = iota
	PACKET_TYPE_GZIP
	PACKET_TYPE_WEB_SOCKET
)

type eventWorker struct {
	incoming   []user.IEventStruct
	status     PROCESS_STATUS
	packetType PACKET_TYPE
	ticker     time.Ticker
}

func (this *eventWorker) Write(event user.IEventStruct) {
	this.incoming = append(this.incoming, event)
	if this.status == PROCESS_STATE_ING {
		// 已经确定包类型，比如确定为gzip等

		// TODO 解包，输出

		// 重置状态

		// 清空数组

	} else {
		// 识别包类型

	}
}

func (this *eventWorker) guessPacket() {

}

func (this *eventWorker) Run() {
	for {
		select {
		case _ = <-this.ticker.C:
			// 输出包
		}
	}

}
