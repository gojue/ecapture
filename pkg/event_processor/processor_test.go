package event_processor

import (
	"ecapture/user"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"time"
)

var (
	testFile = "testdata/all.json"
)

type SSLDataEventTmp struct {
	//Event_type   uint8    `json:"Event_type"`
	DataType     int64      `json:"DataType"`
	Timestamp_ns uint64     `json:"Timestamp_ns"`
	Pid          uint32     `json:"Pid"`
	Tid          uint32     `json:"Tid"`
	Data_len     int32      `json:"Data_len"`
	Comm         [16]byte   `json:"Comm"`
	Fd           uint32     `json:"Fd"`
	Version      int32      `json:"Version"`
	Data         [4096]byte `json:"Data"`
}

func TestEventProcessor_Serve(t *testing.T) {

	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout", "./output.log"}
	cfg.ErrorOutputPaths = []string{"stderr", "./error.log"}
	logger, err := cfg.Build()

	ep := NewEventProcessor(logger)

	go func() {
		ep.Serve()
	}()
	content, err := ioutil.ReadFile(testFile)
	if err != nil {
		//Do something
		log.Fatalf("open file error: %s, file:%s", err.Error(), testFile)
	}
	lines := strings.Split(string(content), "\n")
	//log.Println(lines)
	var i int
	for _, line := range lines {
		if line == "" {
			continue
		}
		//ep.Write(user.NewEventStruct(line))
		var event SSLDataEventTmp
		err := json.Unmarshal([]byte(line), &event)
		if err != nil {
			t.Fatalf("json unmarshal error: %s", err.Error())
		}
		payloadFile := fmt.Sprintf("testdata/%d.bin", event.Timestamp_ns)
		b, e := ioutil.ReadFile(payloadFile)
		if e != nil {
			t.Fatalf("read payload file error: %s, file:%s", e.Error(), payloadFile)
		}
		copy(event.Data[:], b)
		ep.Write(&user.SSLDataEvent{Data_len: event.Data_len, Data: event.Data, DataType: event.DataType, Timestamp_ns: event.Timestamp_ns, Pid: event.Pid, Tid: event.Tid, Comm: event.Comm, Fd: event.Fd, Version: event.Version})
		i++
		if i > 40 {
			break
		}
	}

	tick := time.NewTicker(time.Second * 6)
	select {
	case <-tick.C:
	}
	err = ep.Close()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("done")
}
