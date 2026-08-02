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
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
)

const (
	// ANSI Color codes - 使用更深的颜色以适配白色背景
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorBlack   = "\033[30m" // 黑色，适合白底
	ColorGray    = "\033[90m" // 亮黑色（灰色）

	// Bold colors
	ColorBoldRed     = "\033[1;31m"
	ColorBoldGreen   = "\033[1;32m"
	ColorBoldYellow  = "\033[1;33m"
	ColorBoldBlue    = "\033[1;34m"
	ColorBoldMagenta = "\033[1;35m"
	ColorBoldCyan    = "\033[1;36m"
	ColorBoldBlack   = "\033[1;30m" // 粗体黑色，适合白底

	// Background colors
	BgRed   = "\033[41m"
	BgGreen = "\033[42m"
	BgBlue  = "\033[44m"
)

var (
	wsURL      = flag.String("url", "ws://127.0.0.1:28257", "WebSocket server URL")
	showHex    = flag.Bool("hex", false, "Show payload in hexadecimal format")
	maxPayload = flag.Int("max-payload", 1024, "Maximum payload bytes to display")
	noColor    = flag.Bool("no-color", false, "Disable colored output")
	compact    = flag.Bool("compact", false, "Compact output mode")
)

// ProtobufVisualizer handles protobuf message visualization
type ProtobufVisualizer struct {
	conn           *websocket.Conn
	showHex        bool
	maxPayload     int
	useColor       bool
	compact        bool
	eventCount     int
	heartbeatCount int
	logCount       int
}

// NewProtobufVisualizer creates a new visualizer instance
func NewProtobufVisualizer(url string, showHex bool, maxPayload int, useColor bool, compact bool) (*ProtobufVisualizer, error) {
	conn, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WebSocket server: %w", err)
	}

	return &ProtobufVisualizer{
		conn:       conn,
		showHex:    showHex,
		maxPayload: maxPayload,
		useColor:   useColor,
		compact:    compact,
	}, nil
}

// Close closes the WebSocket connection
func (pv *ProtobufVisualizer) Close() error {
	return pv.conn.Close()
}

// color returns the colored string if color is enabled
func (pv *ProtobufVisualizer) color(color, text string) string {
	if !pv.useColor {
		return text
	}
	return color + text + ColorReset
}

// Listen starts listening for WebSocket messages
func (pv *ProtobufVisualizer) Listen() error {
	pv.printHeader()

	for {
		var msgData []byte
		if err := websocket.Message.Receive(pv.conn, &msgData); err != nil {
			return fmt.Errorf("connection closed: %w", err)
		}

		// Try to unmarshal as LogEntry
		var logEntry pb.LogEntry
		if err := proto.Unmarshal(msgData, &logEntry); err != nil {
			log.Printf("Failed to unmarshal LogEntry: %v", err)
			continue
		}

		pv.visualizeLogEntry(&logEntry)
	}
}

// printHeader prints the application header
func (pv *ProtobufVisualizer) printHeader() {
	if pv.compact {
		return
	}

	header := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    eCapture Protobuf Message Visualizer                      ║
║                                                                              ║
║                         WebSocket Debugging Tool                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
`
	fmt.Println(pv.color(ColorBoldCyan, header))
	fmt.Printf("Connected to: %s\n", pv.color(ColorBoldGreen, *wsURL))
	fmt.Printf("Listening for messages... (Press Ctrl+C to quit)\n\n")
	fmt.Println(strings.Repeat("─", 80))
}

// visualizeLogEntry processes and displays a LogEntry message
func (pv *ProtobufVisualizer) visualizeLogEntry(le *pb.LogEntry) {
	switch le.GetLogType() {
	case pb.LogType_LOG_TYPE_HEARTBEAT:
		pv.heartbeatCount++
		pv.visualizeHeartbeat(le.GetHeartbeatPayload())
	case pb.LogType_LOG_TYPE_PROCESS_LOG:
		pv.logCount++
		pv.visualizeProcessLog(le.GetRunLog())
	case pb.LogType_LOG_TYPE_EVENT:
		pv.eventCount++
		pv.visualizeEvent(le.GetEventPayload())
	default:
		fmt.Printf("%s Unknown log type: %d%s\n",
			pv.color(ColorRed, "⚠️  "),
			le.GetLogType(),
			pv.color(ColorReset, ""))
	}
}

// visualizeHeartbeat displays a heartbeat message
func (pv *ProtobufVisualizer) visualizeHeartbeat(hb *pb.Heartbeat) {
	if pv.compact {
		fmt.Printf("[%s] %s #%d %s\n",
			pv.color(ColorGray, time.Now().Format("15:04:05")),
			pv.color(ColorMagenta, "💓 HEARTBEAT"),
			pv.heartbeatCount,
			pv.color(ColorGray, hb.GetMessage()))
		return
	}

	fmt.Println()
	fmt.Println(pv.color(ColorBoldMagenta, "┌─── 💓 HEARTBEAT ───────────────────────────────────────────────────────"))
	fmt.Printf("│ %s: %s\n",
		pv.color(ColorYellow, "Sequence"),
		pv.color(ColorBlack, fmt.Sprintf("#%d", pv.heartbeatCount)))
	fmt.Printf("│ %s: %s\n",
		pv.color(ColorYellow, "Timestamp"),
		pv.color(ColorBlack, time.Unix(hb.GetTimestamp(), 0).Format("2006-01-02 15:04:05")))
	fmt.Printf("│ %s: %s\n",
		pv.color(ColorYellow, "Count"),
		pv.color(ColorBlack, fmt.Sprintf("%d", hb.GetCount())))
	fmt.Printf("│ %s: %s\n",
		pv.color(ColorYellow, "Message"),
		pv.color(ColorCyan, hb.GetMessage()))
	fmt.Println(pv.color(ColorBoldMagenta, "└────────────────────────────────────────────────────────────────────────"))
}

// visualizeProcessLog displays a process log message
func (pv *ProtobufVisualizer) visualizeProcessLog(log string) {
	if pv.compact {
		fmt.Printf("[%s] %s %s\n",
			pv.color(ColorGray, time.Now().Format("15:04:05")),
			pv.color(ColorGreen, "📋 LOG"),
			pv.color(ColorBlack, log))
		return
	}

	fmt.Println()
	fmt.Println(pv.color(ColorBoldGreen, "┌─── 📋 PROCESS LOG ─────────────────────────────────────────────────────"))
	fmt.Printf("│ %s\n", pv.color(ColorBlack, log))
	fmt.Println(pv.color(ColorBoldGreen, "└────────────────────────────────────────────────────────────────────────"))
}

// visualizeEvent displays an event message with detailed information
func (pv *ProtobufVisualizer) visualizeEvent(event *pb.Event) {
	if event == nil {
		return
	}

	if pv.compact {
		fmt.Printf("[%s] %s #%d PID:%d %s:%d → %s:%d [%d bytes]\n",
			pv.color(ColorGray, time.Now().Format("15:04:05")),
			pv.color(ColorBlue, "📦 EVENT"),
			pv.eventCount,
			event.GetPid(),
			event.GetSrcIp(),
			event.GetSrcPort(),
			event.GetDstIp(),
			event.GetDstPort(),
			event.GetLength())
		return
	}

	fmt.Println()
	fmt.Println(pv.color(ColorBoldBlue, "┌─── 📦 EVENT ───────────────────────────────────────────────────────────"))

	// Event metadata
	fmt.Println(pv.color(ColorBoldCyan, "│ ▶ Metadata:"))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "Sequence"),
		pv.color(ColorBlack, fmt.Sprintf("#%d", pv.eventCount)))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "Timestamp"),
		pv.color(ColorBlack, time.Unix(event.GetTimestamp(), 0).Format("2006-01-02 15:04:05")))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "UUID"),
		pv.color(ColorGray, event.GetUuid()))

	// Process information
	fmt.Println(pv.color(ColorBoldCyan, "│ ▶ Process:"))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "PID"),
		pv.color(ColorBlack, fmt.Sprintf("%d", event.GetPid())))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "Process Name"),
		pv.color(ColorGreen, event.GetPname()))

	// Network information
	if event.GetSrcIp() != "127.0.0.1" || event.GetSrcPort() != 0 {
		fmt.Println(pv.color(ColorBoldCyan, "│ ▶ Network:"))
		fmt.Printf("│   %s: %s → %s\n",
			pv.color(ColorYellow, "Connection"),
			pv.color(ColorMagenta, fmt.Sprintf("%s:%d", event.GetSrcIp(), event.GetSrcPort())),
			pv.color(ColorMagenta, fmt.Sprintf("%s:%d", event.GetDstIp(), event.GetDstPort())))
	}

	// Event details
	fmt.Println(pv.color(ColorBoldCyan, "│ ▶ Event Details:"))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "Type"),
		pv.color(ColorBlack, fmt.Sprintf("%d (%s)", event.GetType(), pv.getEventTypeName(event.GetType()))))
	fmt.Printf("│   %s: %s\n",
		pv.color(ColorYellow, "Length"),
		pv.color(ColorBlack, fmt.Sprintf("%d bytes", event.GetLength())))

	// Payload
	if len(event.GetPayload()) > 0 {
		pv.visualizePayload(event.GetPayload())
	}

	fmt.Println(pv.color(ColorBoldBlue, "└────────────────────────────────────────────────────────────────────────"))
}

// visualizePayload displays the payload in different formats
func (pv *ProtobufVisualizer) visualizePayload(payload []byte) {
	fmt.Println(pv.color(ColorBoldCyan, "│ ▶ Payload:"))

	maxLen := pv.maxPayload
	if len(payload) > maxLen {
		fmt.Printf("│   %s (showing first %d of %d bytes)\n",
			pv.color(ColorYellow, "⚠️  Large payload"),
			maxLen,
			len(payload))
		payload = payload[:maxLen]
	}

	if pv.showHex {
		// Hexadecimal format
		fmt.Println("│   " + pv.color(ColorGray, "Hexadecimal:"))
		hexDump := hex.Dump(payload)
		for _, line := range strings.Split(hexDump, "\n") {
			if line != "" {
				fmt.Println("│   " + pv.color(ColorGray, line))
			}
		}
	} else {
		// Try to display as text
		if isPrintable(payload) {
			// Split payload into lines and add proper indentation
			lines := strings.Split(string(payload), "\n")
			for i, line := range lines {
				// Skip empty last line
				if i == len(lines)-1 && line == "" {
					continue
				}
				fmt.Printf("│   %s\n", pv.color(ColorBlack, line))
			}
		} else {
			// Show a mix of text and hex for binary data
			preview := make([]rune, 0, 64)
			for _, b := range payload[:min(64, len(payload))] {
				if b >= 32 && b <= 126 {
					preview = append(preview, rune(b))
				} else {
					preview = append(preview, '·')
				}
			}
			fmt.Printf("│   %s %s\n",
				pv.color(ColorGray, "Binary data:"),
				pv.color(ColorBlack, string(preview)))
			fmt.Printf("│   %s (use --hex flag to see full hexdump)\n",
				pv.color(ColorYellow, "Tip:"))
		}
	}
}

// getEventTypeName returns a human-readable event type name
func (pv *ProtobufVisualizer) getEventTypeName(eventType uint32) string {
	switch eventType {
	case 0:
		return "Send/Write"
	case 1:
		return "Receive/Read"
	default:
		return "Unknown"
	}
}

// isPrintable checks if the payload contains mostly printable characters
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.8
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// printStats prints statistics before exit
func (pv *ProtobufVisualizer) printStats() {
	if pv.compact {
		return
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println(pv.color(ColorBoldBlack, "Statistics:"))
	fmt.Printf("  %s: %s\n",
		pv.color(ColorYellow, "Events received"),
		pv.color(ColorBlack, fmt.Sprintf("%d", pv.eventCount)))
	fmt.Printf("  %s: %s\n",
		pv.color(ColorYellow, "Heartbeats received"),
		pv.color(ColorBlack, fmt.Sprintf("%d", pv.heartbeatCount)))
	fmt.Printf("  %s: %s\n",
		pv.color(ColorYellow, "Logs received"),
		pv.color(ColorBlack, fmt.Sprintf("%d", pv.logCount)))
	fmt.Println(strings.Repeat("─", 80))
}

func main() {
	flag.Parse()

	useColor := !*noColor

	visualizer, err := NewProtobufVisualizer(*wsURL, *showHex, *maxPayload, useColor, *compact)
	if err != nil {
		log.Fatalf("Failed to create visualizer: %v", err)
		return
	}
	defer func() {
		visualizer.printStats()
		visualizer.Close()
	}()

	if err := visualizer.Listen(); err != nil {
		log.Printf("Visualizer stopped: %v", err)
	}
}
