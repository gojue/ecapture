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
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const maxMessageBytes = 16 << 20

type options struct {
	server     string
	verbose    bool
	keylogFile string
	pcapFile   string
}

func main() {
	var opts options
	flag.StringVar(&opts.server, "server", "ws://127.0.0.1:28257/", "Protobuf v2 subscription URL")
	flag.BoolVar(&opts.verbose, "verbose", false, "show heartbeat records")
	flag.StringVar(&opts.keylogFile, "keylogfile", "", "save KEYLOG events to this new file")
	flag.StringVar(&opts.pcapFile, "pcapfile", "", "save PCAPNG events to this new file")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runClient(ctx, opts, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "receiver:", err)
		os.Exit(1)
	}
}

func runClient(ctx context.Context, opts options, output io.Writer) error {
	dialer := websocket.Dialer{Subprotocols: []string{protocol.Subprotocol}, HandshakeTimeout: 5 * time.Second}
	// The subscription service requires an Origin on non-browser clients too.
	headers := http.Header{"Origin": []string{"http://localhost/"}}
	conn, response, err := dialer.DialContext(ctx, opts.server, headers)
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	if conn.Subprotocol() != protocol.Subprotocol {
		return fmt.Errorf("server did not negotiate %s", protocol.Subprotocol)
	}
	conn.SetReadLimit(maxMessageBytes)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	receiver := &messageReceiver{output: output, verbose: opts.verbose, keylog: artifactFile{path: opts.keylogFile}, pcapng: artifactFile{path: opts.pcapFile}}
	complete, receiveErr := receiveMessages(conn, receiver)
	if err := ctx.Err(); err != nil {
		complete = false
		receiveErr = err
	}
	return errors.Join(receiveErr, receiver.close(complete))
}

func receiveMessages(conn *websocket.Conn, receiver *messageReceiver) (bool, error) {
	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return true, nil
			}
			return false, fmt.Errorf("subscription ended without a normal close; native output remains .partial: %w", err)
		}
		if messageType != websocket.BinaryMessage {
			return false, fmt.Errorf("expected a binary Protobuf message")
		}
		var entry pb.LogEntry
		if err := proto.Unmarshal(data, &entry); err != nil {
			return false, fmt.Errorf("decode v2 record: %w", err)
		}
		if err := receiver.handle(&entry); err != nil {
			return false, err
		}
	}
}

type messageReceiver struct {
	output  io.Writer
	verbose bool
	format  pb.CaptureFormat
	keylog  artifactFile
	pcapng  artifactFile
}

func (r *messageReceiver) handle(entry *pb.LogEntry) error {
	if err := protocol.ValidateLogEntry(entry); err != nil {
		return fmt.Errorf("invalid v2 record: %w", err)
	}
	switch entry.LogType {
	case pb.LogType_LOG_TYPE_PROCESS_LOG:
		return writeLines(r.output, fmt.Sprintf("[log_type=log module=%q] ", entry.Module), entry.GetRunLog())
	case pb.LogType_LOG_TYPE_HEARTBEAT:
		if r.verbose {
			_, err := fmt.Fprintf(r.output, "[log_type=heartbeat module=%q] count=%d\n", entry.Module, entry.GetHeartbeatPayload().Count)
			return err
		}
	case pb.LogType_LOG_TYPE_EVENT:
		event := entry.GetEventPayload()
		if r.format != pb.CaptureFormat_CAPTURE_FORMAT_UNSPECIFIED && r.format != event.CaptureFormat {
			return fmt.Errorf("capture format changed within one subscription; start a new connection and file")
		}
		r.format = event.CaptureFormat
		switch event.CaptureFormat {
		case pb.CaptureFormat_CAPTURE_FORMAT_TEXT:
			return r.displayText(entry.Module, event.GetText())
		case pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG:
			return r.keylog.write(event.GetKeylog().Data, "--keylogfile")
		case pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG:
			return r.pcapng.write(event.GetPcapng().Data, "--pcapfile")
		}
	}
	return nil
}

func (r *messageReceiver) displayText(module string, event *pb.TextEvent) error {
	// Retain every metadata field, including raw argv and TLS observations.
	metadata := proto.Clone(event).(*pb.TextEvent)
	metadata.Payload = nil
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(metadata)
	if err != nil {
		return err
	}
	prefix := fmt.Sprintf("[log_type=event module=%q capture_format=text] ", module)
	if _, err := fmt.Fprintf(r.output, "%s%s\n", prefix, encoded); err != nil {
		return err
	}
	if len(event.Payload) == 0 {
		return nil
	}
	if utf8.Valid(event.Payload) {
		return writeLines(r.output, prefix, string(event.Payload))
	}
	return writeLines(r.output, prefix, hex.Dump(event.Payload))
}

func writeLines(output io.Writer, prefix, value string) error {
	var safe strings.Builder
	for _, char := range value {
		if char < ' ' && char != '\n' && char != '\t' || char == 0x7f {
			fmt.Fprintf(&safe, "\\x%02x", char)
		} else {
			safe.WriteRune(char)
		}
	}
	value = safe.String()
	for _, line := range strings.Split(strings.TrimSuffix(value, "\n"), "\n") {
		if _, err := fmt.Fprintf(output, "%s%s\n", prefix, line); err != nil {
			return err
		}
	}
	return nil
}

func (r *messageReceiver) close(complete bool) error {
	return errors.Join(r.keylog.close(complete, validateKeylog), r.pcapng.close(complete, validatePcapng))
}

type artifactFile struct {
	path string
	file *os.File
}

func (a *artifactFile) write(data []byte, flagName string) error {
	if a.path == "" {
		return fmt.Errorf("received native capture data; select %s", flagName)
	}
	if a.file == nil {
		if _, err := os.Lstat(a.path); err == nil {
			return fmt.Errorf("refusing to replace existing artifact %q", a.path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		file, err := os.OpenFile(a.path+".partial", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("create partial artifact: %w", err)
		}
		a.file = file
	}
	n, err := a.file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func (a *artifactFile) close(complete bool, validate func(io.Reader) error) error {
	if a.file == nil {
		return nil
	}
	err := errors.Join(a.file.Sync(), a.file.Close())
	a.file = nil
	if err != nil || !complete {
		return err
	}
	partial := a.path + ".partial"
	file, err := os.Open(partial)
	if err != nil {
		return err
	}
	err = errors.Join(validate(file), file.Close())
	if err != nil {
		return fmt.Errorf("native output remains %s: %w", partial, err)
	}
	// Link refuses an existing final name; rename could overwrite it.
	if err := os.Link(partial, a.path); err != nil {
		return fmt.Errorf("publish artifact without overwriting: %w", err)
	}
	return os.Remove(partial)
}

func validateKeylog(input io.Reader) error {
	scanner := bufio.NewScanner(input)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) != 0 && data[len(data)-1] != '\n' {
			return 0, nil, fmt.Errorf("unterminated NSS keylog record")
		}
		return bufio.ScanLines(data, atEOF)
	})
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("invalid NSS keylog record")
		}
		random, randomErr := hex.DecodeString(fields[1])
		secret, secretErr := hex.DecodeString(fields[2])
		if randomErr != nil || secretErr != nil || len(random) != 32 || len(secret) == 0 {
			return fmt.Errorf("invalid NSS keylog fields")
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no keylog records received")
	}
	return nil
}

// validatePcapng checks complete block framing and packet presence, not TLS
// decryption or whether the capture was lossless.
func validatePcapng(input io.Reader) error {
	var order binary.ByteOrder
	var header [12]byte
	packets := 0
	for {
		_, err := io.ReadFull(input, header[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("truncated pcapng block: %w", err)
		}
		section := header[0] == 0x0a && header[1] == 0x0d && header[2] == 0x0d && header[3] == 0x0a
		if section {
			switch binary.BigEndian.Uint32(header[8:]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return fmt.Errorf("invalid pcapng byte order")
			}
		}
		if order == nil {
			return fmt.Errorf("pcapng does not start with a section header")
		}
		length := order.Uint32(header[4:8])
		blockType := order.Uint32(header[:4])
		minimum := uint32(12)
		switch blockType {
		case 0x0a0d0d0a:
			minimum = 28
		case 1:
			minimum = 20
		case 6:
			minimum = 32
		}
		if length < minimum || length%4 != 0 || length > maxMessageBytes {
			return fmt.Errorf("invalid pcapng block length %d", length)
		}
		if length == 12 {
			if order.Uint32(header[8:]) != length {
				return fmt.Errorf("pcapng block length trailer mismatch")
			}
			continue
		}
		if _, err := io.CopyN(io.Discard, input, int64(length)-16); err != nil {
			return fmt.Errorf("truncated pcapng block body: %w", err)
		}
		var trailer [4]byte
		if _, err := io.ReadFull(input, trailer[:]); err != nil {
			return err
		}
		if order.Uint32(trailer[:]) != length {
			return fmt.Errorf("pcapng block length trailer mismatch")
		}
		if blockType == 3 || blockType == 6 {
			packets++
		}
	}
	if packets == 0 {
		return fmt.Errorf("no pcapng packet blocks received")
	}
	return nil
}
