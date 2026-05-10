package event_processor

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	testFile = "testdata/all.json"
)

type SSLDataEventTmp struct {
	//Event_type   uint8    `json:"Event_type"`
	DataType  int64       `json:"DataType"`
	Timestamp uint64      `json:"Timestamp"`
	Pid       uint32      `json:"Pid"`
	Tid       uint32      `json:"Tid"`
	DataLen   int32       `json:"DataLen"`
	Comm      [16]byte    `json:"Comm"`
	Fd        uint32      `json:"Fd"`
	Version   int32       `json:"Version"`
	Data      [16384]byte `json:"Data"`
}

func TestEventProcessor_Serve(t *testing.T) {

	logger := log.Default()
	//var buf bytes.Buffer
	//logger.SetOutput(&buf)
	var output = "./output.log"
	f, e := os.Create(output)
	if e != nil {
		t.Fatal(e)
		return
	}
	logger.SetOutput(f)
	// no truncate
	ep := NewEventProcessor(f, true, 0)
	go func() {
		var err error
		err = ep.Serve()
		if err != nil {
			//log.Fatalf(err.Error())
			t.Error(err)
			return
		}
	}()
	content, err := os.ReadFile(testFile)
	if err != nil {
		//Do something
		t.Fatalf("open file error: %s, file:%s", err.Error(), testFile)
	}
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		var eventSSL SSLDataEventTmp
		err := json.Unmarshal([]byte(line), &eventSSL)
		if err != nil {
			t.Fatalf("json unmarshal error: %s, body:%v", err.Error(), line)
		}
		payloadFile := fmt.Sprintf("testdata/%d.bin", eventSSL.Timestamp)
		b, e := os.ReadFile(payloadFile)
		if e != nil {
			t.Fatalf("read payload file error: %s, file:%s", e.Error(), payloadFile)
		}
		copy(eventSSL.Data[:], b)
		ep.Write(&BaseEvent{DataLen: eventSSL.DataLen, Data: eventSSL.Data, DataType: eventSSL.DataType, Timestamp: eventSSL.Timestamp, Pid: eventSSL.Pid, Tid: eventSSL.Tid, Comm: eventSSL.Comm, Fd: eventSSL.Fd, Version: eventSSL.Version})
	}

	tick := time.NewTicker(time.Second * 10)
	<-tick.C

	err = ep.Close()
	logger.SetOutput(io.Discard)
	bufString, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
		return
	}

	lines = strings.Split(string(bufString), "\n")
	ok := true
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "dump") {
			t.Log(line)
			ok = false
		}
		// http2 parse error log
		if strings.Contains(line, "[http2 re") {
			t.Log(line)
			ok = false
		}

	}
	if err != nil {
		t.Fatalf("close error: %s", err.Error())
	}

	if !ok {
		t.Fatalf("some errors occurred")
		return
	}
	//t.Log(string(bufString))
	t.Log("done")
}

func Test_Truncated_EventProcessor_Serve(t *testing.T) {

	logger := log.Default()
	//var buf bytes.Buffer
	//logger.SetOutput(&buf)
	var output = "./output_truncated.log"
	f, e := os.Create(output)
	if e != nil {
		t.Fatal(e)
		return
	}
	logger.SetOutput(f)

	// truncate 1000 bytes
	ep := NewEventProcessor(f, true, 1000)
	go func() {
		var err error
		err = ep.Serve()
		if err != nil {
			//log.Fatalf(err.Error())
			t.Error(err)
			return
		}
	}()

	lines := []string{
		// short, no truncated
		`{"DataType":0,"Timestamp":952253597324253,"Pid":469929,"Tid":469929,"DataLen":308,"Comm":[119,103,101,116,0,0,0,0,0,0,0,0,0,0,0,0],"Fd":3,"Version":771}`,
		// long, should truncated
		`{"DataType":0,"Timestamp":952282712204824,"Pid":469953,"Tid":469953,"DataLen":4096,"Comm":[99,117,114,108,0,0,0,0,0,0,0,0,0,0,0,0],"Fd":5,"Version":771}`,
	}

	for _, line := range lines {
		if line == "" {
			continue
		}
		var eventSSL SSLDataEventTmp
		err := json.Unmarshal([]byte(line), &eventSSL)
		if err != nil {
			t.Fatalf("json unmarshal error: %s, body:%v", err.Error(), line)
		}
		payloadFile := fmt.Sprintf("testdata/%d.bin", eventSSL.Timestamp)
		b, e := os.ReadFile(payloadFile)
		if e != nil {
			t.Fatalf("read payload file error: %s, file:%s", e.Error(), payloadFile)
		}
		copy(eventSSL.Data[:], b)
		ep.Write(&BaseEvent{DataLen: eventSSL.DataLen, Data: eventSSL.Data, DataType: eventSSL.DataType, Timestamp: eventSSL.Timestamp, Pid: eventSSL.Pid, Tid: eventSSL.Tid, Comm: eventSSL.Comm, Fd: eventSSL.Fd, Version: eventSSL.Version})
	}

	tick := time.NewTicker(time.Second * 10)
	<-tick.C

	err := ep.Close()
	logger.SetOutput(io.Discard)
	bufString, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
		return
	}

	lines = strings.Split(string(bufString), "\n")
	ok := true
	for _, line := range lines {
		// truncated once
		if strings.Contains(line, "Events truncated, size:") {
			t.Log(line)
		}
	}

	if err != nil {
		t.Fatalf("close error: %s", err.Error())
	}

	if !ok {
		t.Fatalf("some errors occurred")
		return
	}
	//t.Log(string(bufString))
	t.Log("done")
}

// TestEventProcessor_ImmediateClose verifies that calling Close() immediately
// after writing events (without waiting for worker idle-timeout) still flushes
// all captured data before Close() returns.  This is the regression test for
// the "workerQueue is not empty" data-loss bug.
//
// Correctness note: Serve() may not have entered its select loop by the time
// Close() is called.  This is safe because Close() blocks on serveDone until
// Serve() runs, processes all remaining events (via drain()), and closes
// serveDone.  The already-closed closeChan persists so Serve() sees it
// whenever it starts.
func TestEventProcessor_ImmediateClose(t *testing.T) {
	output := "./output_immediate_close.log"
	f, e := os.Create(output)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = os.Remove(output) }()

	ep := NewEventProcessor(f, false, 0)
	// Serve() must be started before Close() is called.
	go func() {
		if err := ep.Serve(); err != nil {
			t.Error(err)
		}
	}()

	// Write a small known payload.
	const testPayload = "hello_immediate_close"
	var comm [16]byte
	copy(comm[:], "testcomm")
	var data [MaxDataSize]byte
	copy(data[:], testPayload)
	ep.Write(&BaseEvent{
		DataLen:   int32(len(testPayload)),
		Data:      data,
		DataType:  int64(ProbeEntry),
		Timestamp: 1,
		Pid:       1,
		Tid:       1,
		Comm:      comm,
		Fd:        1,
		Version:   int32(Tls12Version),
	})

	// Close immediately — do NOT wait for worker idle-timeout.
	// The fix must ensure Close() blocks until the payload is flushed.
	if err := ep.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("file Close() error: %v", err)
	}

	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 {
		t.Fatal("output file is empty; captured data was lost on shutdown")
	}
	t.Logf("output (%d bytes) written correctly", len(content))
}
