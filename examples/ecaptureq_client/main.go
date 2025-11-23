// Copyright 2025 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

var (
	serverURL = flag.String("server", "ws://127.0.0.1:28257/", "WebSocket server URL")
	verbose   = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	log.Printf("Connecting to eCapture WebSocket server at %s", *serverURL)

	// Connect to WebSocket server
	ws, err := websocket.Dial(*serverURL, "", "http://localhost/")
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer ws.Close()

	log.Println("Connected successfully!")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Channel to signal goroutine to stop
	done := make(chan struct{})

	// Start receiving messages in a goroutine
	go func() {
		defer close(done)
		receiveMessages(ws)
	}()

	// Wait for interrupt signal
	<-sigChan
	log.Println("\nShutting down...")
}

func receiveMessages(ws *websocket.Conn) {
	for {
		var msgData []byte
		err := websocket.Message.Receive(ws, &msgData)
		if err != nil {
			log.Printf("Connection closed: %v", err)
			return
		}

		// Decode protobuf message
		var logEntry pb.LogEntry
		err = proto.Unmarshal(msgData, &logEntry)
		if err != nil {
			log.Printf("Failed to unmarshal protobuf message: %v", err)
			continue
		}

		// Handle different message types
		handleLogEntry(&logEntry)
	}
}

func handleLogEntry(logEntry *pb.LogEntry) {
	switch logEntry.LogType {
	case pb.LogType_LOG_TYPE_HEARTBEAT:
		handleHeartbeat(logEntry)
	case pb.LogType_LOG_TYPE_PROCESS_LOG:
		handleProcessLog(logEntry)
	case pb.LogType_LOG_TYPE_EVENT:
		handleEvent(logEntry)
	default:
		log.Printf("Unknown log type: %v", logEntry.LogType)
	}
}

func handleHeartbeat(logEntry *pb.LogEntry) {
	hb := logEntry.GetHeartbeatPayload()
	if hb == nil {
		log.Println("Received heartbeat with nil payload")
		return
	}

	if *verbose {
		log.Printf("[HEARTBEAT] Count: %d, Time: %s, Message: %s",
			hb.Count,
			time.Unix(hb.Timestamp, 0).Format(time.RFC3339),
			hb.Message)
	}
}

func handleProcessLog(logEntry *pb.LogEntry) {
	logMsg := logEntry.GetRunLog()
	fmt.Print(logMsg)
}

func handleEvent(logEntry *pb.LogEntry) {
	event := logEntry.GetEventPayload()
	if event == nil {
		log.Println("Received event with nil payload")
		return
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("🔍 Captured Event\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if event.Timestamp > 0 {
		fmt.Printf("📅 Timestamp:    %s\n", time.Unix(event.Timestamp, 0).Format(time.RFC3339))
	}
	if event.Uuid != "" {
		fmt.Printf("🆔 UUID:         %s\n", event.Uuid)
	}
	if event.Pid > 0 {
		fmt.Printf("🔢 PID:          %d\n", event.Pid)
	}
	if event.Pname != "" {
		fmt.Printf("📝 Process:      %s\n", event.Pname)
	}
	if event.SrcIp != "" && event.SrcPort > 0 {
		fmt.Printf("🔗 Source:       %s:%d\n", event.SrcIp, event.SrcPort)
	}
	if event.DstIp != "" && event.DstPort > 0 {
		fmt.Printf("🎯 Destination:  %s:%d\n", event.DstIp, event.DstPort)
	}
	if event.Type > 0 {
		fmt.Printf("📊 Type:         %d\n", event.Type)
	}
	if event.Length > 0 {
		fmt.Printf("📏 Length:       %d bytes\n", event.Length)
	}

	// Display payload
	if len(event.Payload) > 0 {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("📦 Payload:")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		// Try to display as text first
		if isPrintable(event.Payload) {
			fmt.Println(string(event.Payload))
		} else {
			// Display as hex dump
			fmt.Println("Hex dump:")
			printHexDump(event.Payload)
		}

		// Also provide base64 encoding
		fmt.Println("\nBase64 encoded:")
		encoded := base64.StdEncoding.EncodeToString(event.Payload)
		// Print in chunks of 80 characters
		for i := 0; i < len(encoded); i += 80 {
			end := i + 80
			if end > len(encoded) {
				end = len(encoded)
			}
			fmt.Println(encoded[i:end])
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

// isPrintable checks if the byte slice contains mostly printable ASCII characters
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}

	// Consider it printable if more than 90% of characters are printable
	return float64(printableCount)/float64(len(data)) > 0.9
}

// printHexDump prints data in hex dump format
func printHexDump(data []byte) {
	const bytesPerLine = 16

	for i := 0; i < len(data); i += bytesPerLine {
		// Print offset
		fmt.Printf("%08x  ", i)

		// Print hex values
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}

			// Add extra space in the middle
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// Print ASCII representation
		fmt.Print(" |")
		for j := 0; j < bytesPerLine && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}
