// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
	"github.com/gojue/ecapture/v2/pkg/util/kernel"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
	protocol "github.com/gojue/ecapture/v2/protobuf/v2"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	server        = flag.String("server", "", "Protobuf v2 WebSocket URL")
	listen        = flag.String("listen", "", "listen for a JSON Lines TCP producer")
	jsonInput     = flag.String("json-input", "", "read an existing JSON Lines output file")
	extractEvents = flag.String("extract-events", "", "write decoded event bytes to this file")
	extractLogs   = flag.String("extract-logs", "", "write operational log messages to this file")
	captureFile   = flag.String("capture-file", "", "save received native KEYLOG/PCAPNG bytes")
	logsOnly      = flag.Bool("logs-only", false, "require operational logs and reject every EVENT")
	readyFile     = flag.String("ready-file", "", "write when the listener/subscription is ready")
	drain         = flag.Bool("drain", false, "read until connection end after assertions are satisfied")
	module        = flag.String("module", "", "required canonical module on captured events")
	format        = flag.String("format", "text", "required capture format")
	sensitive     = flag.Bool("sensitive", false, "require sensitive text metadata")
	token         = flag.String("token", "", "required text payload token")
	argsToken     = flag.String("args-token", "", "required argv token for the expected request process")
	tlsMetadata   = flag.Bool("tls-metadata", false, "require decrypted TLS handshake observations")
	pidFile       = flag.String("pid-file", "", "file containing the expected captured request PID")
	execClient    = flag.Bool("exec", false, "record the kernel TGID in --pid-file, then exec the command after --")
	wait          = flag.Duration("timeout", 20*time.Second, "overall timeout")
)

func main() {
	flag.Parse()
	if *execClient {
		if err := recordPIDAndExec(*pidFile, flag.Args()); err != nil {
			fatalf("start request process: %v", err)
		}
		return
	}
	if err := runAssertions(); err != nil {
		fatalf("%v", err)
	}
}

func runAssertions() error {
	wantFormat, err := parseFormat(*format)
	if err != nil {
		return err
	}
	count := 0
	for _, value := range []string{*server, *listen, *jsonInput} {
		if value != "" {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("select exactly one of --server, --listen, --json-input")
	}
	if *captureFile != "" && *extractEvents != "" {
		return fmt.Errorf("select --capture-file or --extract-events")
	}
	eventPath := *extractEvents
	if *captureFile != "" {
		eventPath = *captureFile
	}
	for _, destination := range []string{eventPath, *extractLogs} {
		if destination != "" && *jsonInput != "" {
			a, _ := filepath.Abs(destination)
			b, _ := filepath.Abs(*jsonInput)
			if a == b {
				return fmt.Errorf("extracted output cannot replace JSON input")
			}
		}
	}
	eventOutput, err := openOutput(eventPath)
	if err != nil {
		return err
	}
	defer eventOutput.Close()
	logOutput, err := openOutput(*extractLogs)
	if err != nil {
		return err
	}
	defer logOutput.Close()
	state := &assertionState{wantFormat: wantFormat, requireSensitive: *sensitive, requiredToken: *token, requiredArgs: *argsToken, requiredPIDFile: *pidFile, requiredModule: *module, requireTLS: *tlsMetadata, logsOnly: *logsOnly, eventOutput: eventOutput, logOutput: logOutput, process: *pidFile == ""}
	// Offline extraction may legitimately contain only diagnostics. Sensitivity
	// constrains text records when present; token/process assertions require events.
	state.allowNoEvents = *jsonInput != "" && *token == "" && *argsToken == "" && *pidFile == "" && *module == "" && !*tlsMetadata
	deadline := time.Now().Add(*wait)
	var next func() ([]byte, error)
	binaryMessages := false
	if *jsonInput != "" {
		input, err := os.Open(*jsonInput)
		if err != nil {
			return err
		}
		defer input.Close()
		next = jsonLines(input)
	} else if *listen != "" {
		address, err := net.ResolveTCPAddr("tcp", *listen)
		if err != nil {
			return err
		}
		listener, err := net.ListenTCP("tcp", address)
		if err != nil {
			return err
		}
		defer listener.Close()
		_ = listener.SetDeadline(deadline)
		if err := signalReady(listener.Addr().String()); err != nil {
			return err
		}
		conn, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		next = jsonLines(conn)
	} else {
		var conn *websocket.Conn
		for time.Now().Before(deadline) {
			conn, err = dialSubscription(*server, deadline)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if conn == nil {
			return fmt.Errorf("connect: %w", err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(deadline)
		conn.SetReadLimit(16 << 20)
		if err := signalReady(*server); err != nil {
			return err
		}
		binaryMessages = true
		next = func() ([]byte, error) {
			return readBinaryMessage(conn)
		}
	}
	for {
		data, err := next()
		if err != nil {
			if errors.Is(err, io.EOF) && state.satisfied() {
				break
			}
			return fmt.Errorf("receive before requirements were met: %w", err)
		}
		entry := &pb.LogEntry{}
		if binaryMessages {
			err = proto.Unmarshal(data, entry)
		} else {
			err = protojson.Unmarshal(data, entry)
		}
		if err != nil {
			return fmt.Errorf("decode v2 record: %w", err)
		}
		if err := state.consume(entry); err != nil {
			return err
		}
		if *jsonInput == "" && !*drain && !*logsOnly && state.satisfied() {
			break
		}
	}
	if !state.satisfied() {
		return fmt.Errorf("requirements not met: PROCESS_LOG=%v EVENT=%v PROCESS=%v", state.processLog, state.event, state.process)
	}
	if err := errors.Join(eventOutput.Sync(), logOutput.Sync()); err != nil {
		return err
	}
	check := "METADATA"
	if wantFormat != pb.CaptureFormat_CAPTURE_FORMAT_TEXT {
		check = "NATIVE"
	}
	fmt.Printf("PROCESS_LOG=%d EVENT=%d FORMAT=%s %s=1\n", boolInt(state.processLog), boolInt(state.event), wantFormat.String(), check)
	return nil
}

func dialSubscription(address string, deadline time.Time) (*websocket.Conn, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	dialer := websocket.Dialer{Subprotocols: []string{protocol.Subprotocol}, HandshakeTimeout: 5 * time.Second}
	conn, response, err := dialer.DialContext(ctx, address, http.Header{"Origin": []string{"http://localhost/"}})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		_ = conn.Close()
		return nil, fmt.Errorf("server did not negotiate %s", protocol.Subprotocol)
	}
	return conn, nil
}

func readBinaryMessage(conn *websocket.Conn) ([]byte, error) {
	messageType, data, err := conn.ReadMessage()
	if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		return nil, io.EOF
	}
	if err != nil {
		// Only close 1000 means the producer drained successfully. In particular,
		// a raw EOF or close 1011 must not satisfy the caller's completion check.
		return nil, fmt.Errorf("subscription ended without a normal close: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		return nil, fmt.Errorf("expected a binary Protobuf frame")
	}
	return data, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func signalReady(value string) error {
	if *readyFile == "" {
		return nil
	}
	return os.WriteFile(*readyFile, []byte(value+"\n"), 0o600)
}

type outputFile struct{ file *os.File }

func openOutput(path string) (*outputFile, error) {
	if path == "" {
		return &outputFile{}, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	return &outputFile{file: file}, err
}
func (o *outputFile) Write(data []byte) (int, error) {
	if o.file == nil {
		return len(data), nil
	}
	return o.file.Write(data)
}
func (o *outputFile) Close() error {
	if o.file == nil {
		return nil
	}
	return o.file.Close()
}
func (o *outputFile) Sync() error {
	if o.file == nil {
		return nil
	}
	return o.file.Sync()
}

func jsonLines(reader io.Reader) func() ([]byte, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 64<<20)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) > 0 && data[len(data)-1] != '\n' {
			return 0, nil, fmt.Errorf("incomplete JSON Lines record")
		}
		return bufio.ScanLines(data, atEOF)
	})
	return func() ([]byte, error) {
		if scanner.Scan() {
			return scanner.Bytes(), nil
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
}

type assertionState struct {
	wantFormat                                                   pb.CaptureFormat
	requireSensitive                                             bool
	requiredToken, requiredArgs, requiredPIDFile, requiredModule string
	requireTLS, logsOnly                                         bool
	allowNoEvents                                                bool
	records                                                      int
	processLog, event, process                                   bool
	native                                                       bytes.Buffer
	eventOutput, logOutput                                       io.Writer
}

func (s *assertionState) satisfied() bool {
	if s.allowNoEvents && !s.logsOnly {
		return s.records > 0 && (s.native.Len() == 0 || nativeReady(s.wantFormat, s.native.Bytes()))
	}
	return s.processLog && (s.logsOnly || (s.event && s.process))
}

func (s *assertionState) consume(entry *pb.LogEntry) error {
	if err := protocol.ValidateLogEntry(entry); err != nil {
		return fmt.Errorf("invalid record: %w", err)
	}
	s.records++
	switch entry.LogType {
	case pb.LogType_LOG_TYPE_PROCESS_LOG:
		if entry.GetRunLog() == "" {
			return fmt.Errorf("PROCESS_LOG payload is empty")
		}
		if s.requiredToken != "" && strings.Contains(entry.GetRunLog(), s.requiredToken) {
			return fmt.Errorf("captured token leaked into PROCESS_LOG")
		}
		if s.requiredArgs != "" && strings.Contains(entry.GetRunLog(), s.requiredArgs) {
			return fmt.Errorf("captured argv leaked into PROCESS_LOG")
		}
		s.processLog = true
		_, err := fmt.Fprintln(s.logOutput, entry.GetRunLog())
		return err
	case pb.LogType_LOG_TYPE_EVENT:
		if s.logsOnly {
			return fmt.Errorf("EVENT found in a logs-only destination")
		}
		if s.requiredModule != "" && entry.Module != s.requiredModule {
			return fmt.Errorf("module=%q want=%q", entry.Module, s.requiredModule)
		}
		event := entry.GetEventPayload()
		if event.CaptureFormat != s.wantFormat {
			return fmt.Errorf("capture format=%s want=%s", event.CaptureFormat, s.wantFormat)
		}
		if err := validateEvent(event, s.wantFormat, s.requireSensitive); err != nil {
			return err
		}
		var payload []byte
		switch event.CaptureFormat {
		case pb.CaptureFormat_CAPTURE_FORMAT_TEXT:
			text := event.GetText()
			payload = text.Payload
			if !s.process && text.Direction == "request" {
				data, err := os.ReadFile(s.requiredPIDFile)
				if err != nil {
					return err
				}
				expected, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid expected PID")
				}
				if err := validateProcess(text, expected, s.requiredArgs); err != nil {
					return err
				}
				s.process = true
			}
			if s.requiredToken == "" || bytes.Contains(payload, []byte(s.requiredToken)) {
				if s.requireTLS {
					info := text.Tls
					if info["version"] != "TLS 1.3" || info["cipher_suite"] == "" || len(info["ja3"]) != 32 || !strings.HasPrefix(info["ja4"], "t13") {
						return fmt.Errorf("TLS handshake metadata missing or invalid")
					}
				}
				s.event = true
			}
		case pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG:
			payload = event.GetKeylog().Data
		case pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG:
			payload = event.GetPcapng().Data
		}
		if event.CaptureFormat != pb.CaptureFormat_CAPTURE_FORMAT_TEXT {
			if s.native.Len()+len(payload) > 64<<20 {
				return fmt.Errorf("native E2E capture exceeds assertion buffer limit")
			}
			_, _ = s.native.Write(payload)
			s.event = nativeReady(s.wantFormat, s.native.Bytes())
		}
		n, err := s.eventOutput.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		return err
	}
	return nil
}

func nativeReady(format pb.CaptureFormat, data []byte) bool {
	if format == pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG {
		if len(data) == 0 || data[len(data)-1] != '\n' {
			return false
		}
		count := 0
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				return false
			}
			random, er := hex.DecodeString(fields[1])
			secret, es := hex.DecodeString(fields[2])
			if er != nil || es != nil || len(random) != 32 || len(secret) == 0 {
				return false
			}
			count++
		}
		return count > 0
	}
	var order binary.ByteOrder
	packet, secret, iface := false, false, false
	for len(data) > 0 {
		if len(data) < 12 {
			return false
		}
		if bytes.Equal(data[:4], []byte{10, 13, 13, 10}) {
			switch binary.BigEndian.Uint32(data[8:12]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return false
			}
		}
		if order == nil {
			return false
		}
		size := order.Uint32(data[4:8])
		if size < 12 || size%4 != 0 || uint64(size) > uint64(len(data)) || order.Uint32(data[size-4:size]) != size {
			return false
		}
		switch order.Uint32(data[:4]) {
		case 0x0a0d0d0a:
			if size < 28 {
				return false
			}
		case 1:
			if size < 20 {
				return false
			}
			iface = true
		case 3:
			if size < 20 || !iface {
				return false
			}
			packet = true
		case 6:
			if size < 32 || !iface {
				return false
			}
			captured := order.Uint32(data[20:24])
			if captured == 0 || uint64(captured)+32 > uint64(size) {
				return false
			}
			packet = true
		case 10:
			if size < 20 || order.Uint32(data[8:12]) != 0x544c534b {
				return false
			}
			length := order.Uint32(data[12:16])
			if uint64(length)+20 > uint64(size) {
				return false
			}
			secret = secret || nativeReady(pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, data[16:16+length])
		}
		data = data[size:]
	}
	return packet && secret && iface
}

func validateProcess(event *pb.TextEvent, expected int64, requiredArg string) error {
	nameValid := event.GetPname() != "" && event.GetPname() != "decryptor"
	if expected <= 0 || event.GetPid() != expected || !nameValid {
		return fmt.Errorf("request process attribution mismatch: expected_pid=%d captured_pid=%d name_valid=%v", expected, event.GetPid(), nameValid)
	}
	if requiredArg != "" && (!bytes.Contains(event.GetProcessArgs(), []byte(requiredArg)) || event.GetProcessArgsTruncated()) {
		return fmt.Errorf("request process arguments are missing or truncated: bytes=%d truncated=%v", len(event.GetProcessArgs()), event.GetProcessArgsTruncated())
	}
	return nil
}

func validateEvent(event *pb.Event, wantFormat pb.CaptureFormat, sensitiveText bool) error {
	if err := protocol.ValidateEvent(event); err != nil {
		return err
	}
	if event.CaptureFormat != wantFormat {
		return fmt.Errorf("unexpected capture format")
	}
	if wantFormat != pb.CaptureFormat_CAPTURE_FORMAT_TEXT {
		return nil
	}
	text := event.GetText()
	if text.Timestamp == 0 || text.Sequence == 0 {
		return fmt.Errorf("text timestamp or sequence is zero")
	}
	// Length describes the formatted payload. OriginalLength retains capture or
	// SDK bytes before text prefixes/hex rendering, so either length may be larger.
	want := pb.Sensitivity_SENSITIVITY_NORMAL
	if sensitiveText {
		want = pb.Sensitivity_SENSITIVITY_SENSITIVE
	}
	if text.Sensitivity != want {
		return fmt.Errorf("sensitivity=%s want=%s", text.Sensitivity, want)
	}
	return nil
}

// The collector exports the initial PID namespace's TGID, whereas os.Getpid
// (and shell $$) is namespace-local. Observe only our nonce-named thread
// before exec, which preserves the TGID. This also works on kernels predating
// bpf_get_ns_current_pid_tgid and does not depend on host procfs being mounted.
func recordPIDAndExec(path string, command []string) error {
	if path == "" || len(command) == 0 {
		return fmt.Errorf("--exec requires --pid-file and a command")
	}
	pid, err := kernelTGID()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(strconv.FormatUint(uint64(pid), 10)+"\n"), 0o600); err != nil {
		return err
	}
	return syscall.Exec(command[0], command, os.Environ())
}

func kernelTGID() (uint32, error) {
	minimum, supported := map[string]kernel.Version{
		"amd64": kernel.VersionCode(4, 18, 0), "arm64": kernel.VersionCode(5, 5, 0), "loong64": kernel.VersionCode(6, 6, 0),
	}[runtime.GOARCH]
	if runtime.GOOS != "linux" || !supported {
		return 0, fmt.Errorf("unsupported PID observer platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	version, err := kernel.HostVersion()
	if err != nil {
		return 0, err
	}
	if version < minimum {
		return 0, fmt.Errorf("PID observer requires kernel >= %s", minimum)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return 0, err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	var marker [16]byte
	copy(marker[:], fmt.Sprintf("ecap%x", nonce[:5]))
	result, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		return 0, err
	}
	defer result.Close()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "e2e_request_pid", Type: ebpf.RawTracepoint, License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16),
			asm.Mov.Imm(asm.R2, 16), asm.FnGetCurrentComm.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord),
			asm.LoadImm(asm.R3, int64(binary.LittleEndian.Uint64(marker[:8])), asm.DWord),
			asm.JNE.Reg(asm.R2, asm.R3, "done"),
			asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord),
			asm.LoadImm(asm.R3, int64(binary.LittleEndian.Uint64(marker[8:])), asm.DWord),
			asm.JNE.Reg(asm.R2, asm.R3, "done"),
			asm.FnGetCurrentPidTgid.Call(),
			asm.RSh.Imm(asm.R0, 32),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
			asm.StoreImm(asm.RFP, -8, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, result.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -4),
			asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return(),
		},
	})
	if err != nil {
		return 0, err
	}
	defer program.Close()
	attachment, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: program})
	if err != nil {
		return 0, err
	}
	defer attachment.Close()
	// Raw tracepoints need neither tracefs nor architecture-specific pt_regs.
	// Pin and restore the calling thread's name, even when observation fails.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var original [16]byte
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_NAME, uintptr(unsafe.Pointer(&original[0])), 0, 0, 0, 0); errno != 0 {
		return 0, errno
	}
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(&marker[0])), 0, 0, 0, 0); errno != 0 {
		return 0, errno
	}
	defer func() {
		_, _, _ = unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(&original[0])), 0, 0, 0, 0)
	}()
	_, _, _ = syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	var pid uint32
	if err := result.Lookup(uint32(0), &pid); err != nil {
		return 0, err
	}
	if pid == 0 {
		return 0, fmt.Errorf("request kernel TGID was not observed")
	}
	return pid, nil
}

func parseFormat(value string) (pb.CaptureFormat, error) {
	switch value {
	case handlers.ModeText:
		return pb.CaptureFormat_CAPTURE_FORMAT_TEXT, nil
	case handlers.ModeKeylog:
		return pb.CaptureFormat_CAPTURE_FORMAT_KEYLOG, nil
	case handlers.ModePcapng:
		return pb.CaptureFormat_CAPTURE_FORMAT_PCAPNG, nil
	default:
		return pb.CaptureFormat_CAPTURE_FORMAT_UNSPECIFIED, fmt.Errorf("unsupported format %q", value)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "ECAPTUREQ_ASSERTION: "+format+"\n", args...)
	os.Exit(1)
}
