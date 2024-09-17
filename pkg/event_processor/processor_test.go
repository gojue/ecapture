package event_processor

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"strings"
	"testing"
	"time"
)

// ZeroLog print level
const (
	eTestEventLevel        = zerolog.Level(88)
	eTestEventName         = "[DATA]"
	eTestEventConsoleColor = 35 // colorMagenta
)

var (
	testFile = "testdata/all.json"
)

type SSLDataEventTmp struct {
	//Event_type   uint8    `json:"Event_type"`
	DataType  int64      `json:"DataType"`
	Timestamp uint64     `json:"Timestamp"`
	Pid       uint32     `json:"Pid"`
	Tid       uint32     `json:"Tid"`
	DataLen   int32      `json:"DataLen"`
	Comm      [16]byte   `json:"Comm"`
	Fd        uint32     `json:"Fd"`
	Version   int32      `json:"Version"`
	Data      [4096]byte `json:"Data"`
}

type eventTestWriter struct {
	logger *zerolog.Logger
}

func (e eventTestWriter) Write(p []byte) (n int, err error) {
	e.logger.WithLevel(eTestEventLevel).Msgf("%s", p)
	return len(p), nil
}

func initTestLogger(stdoutFile string) (*zerolog.Logger, error) {
	var logger zerolog.Logger
	// append zerolog Global variables
	zerolog.FormattedLevels[eTestEventLevel] = eTestEventName
	zerolog.LevelColors[eTestEventLevel] = eTestEventConsoleColor

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	f, err := os.Create(stdoutFile)
	if err != nil {
		return nil, err
	}
	multi := zerolog.MultiLevelWriter(consoleWriter, f)
	logger = zerolog.New(multi).With().Timestamp().Logger()
	return &logger, nil
}

func TestEventProcessor_Serve(t *testing.T) {

	var output = "./output.log"
	lger, err := initTestLogger(output)
	if err != nil {
		t.Fatalf("init logger error: %s", err.Error())
	}
	var ecw = eventTestWriter{logger: lger}

	ep := NewEventProcessor(lger, ecw, true, "ecapture_test", "1.0.0")
	go func() {
		var err error
		err = ep.Serve()
		if err != nil {
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
	//logger.SetOutput(io.Discard)
	bufString, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
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
	}
	//t.Log(string(bufString))
	t.Log("done")
}
