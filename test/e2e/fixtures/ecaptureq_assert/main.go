// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
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
	"golang.org/x/net/websocket"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
)

var (
	server      = flag.String("server", "", "eCaptureQ WebSocket URL")
	format      = flag.String("format", "text", "required capture format")
	sensitive   = flag.Bool("sensitive", false, "require sensitive text metadata")
	token       = flag.String("token", "", "required text payload token")
	argsToken   = flag.String("args-token", "", "required argv token for the expected request process")
	tlsMetadata = flag.Bool("tls-metadata", false, "require decrypted TLS handshake observations")
	pidFile     = flag.String("pid-file", "", "file containing the expected captured request PID")
	execClient  = flag.Bool("exec", false, "record the kernel TGID in --pid-file, then exec the command after --")
	wait        = flag.Duration("timeout", 20*time.Second, "overall timeout")
)

func main() {
	flag.Parse()
	if *execClient {
		if err := recordPIDAndExec(*pidFile, flag.Args()); err != nil {
			fatalf("start request process: %v", err)
		}
		return
	}
	deadline := time.Now().Add(*wait)
	var conn *websocket.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = websocket.Dial(*server, "", "http://localhost/")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fatalf("connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	wantFormat, err := parseFormat(*format)
	if err != nil {
		fatalf("%v", err)
	}
	var processLog, event bool
	process := *pidFile == ""
	for time.Now().Before(deadline) {
		var data []byte
		if err := websocket.Message.Receive(conn, &data); err != nil {
			fatalf("receive before requirements were met: %v", err)
		}
		entry := &pb.LogEntry{}
		if err := proto.Unmarshal(data, entry); err != nil {
			fatalf("decode protobuf: %v", err)
		}
		switch entry.GetLogType() {
		case pb.LogType_LOG_TYPE_PROCESS_LOG:
			if entry.GetRunLog() == "" {
				fatalf("PROCESS_LOG payload is empty")
			}
			processLog = true
			if *token != "" && strings.Contains(entry.GetRunLog(), *token) {
				fatalf("captured token leaked into PROCESS_LOG")
			}
		case pb.LogType_LOG_TYPE_EVENT:
			captured := entry.GetEventPayload()
			if captured == nil || captured.GetCaptureFormat() != wantFormat {
				continue
			}
			if err := validateEvent(captured, wantFormat, *sensitive); err != nil {
				fatalf("invalid EVENT metadata: %v", err)
			}
			if !process && captured.GetDirection() == "request" {
				data, err := os.ReadFile(*pidFile)
				if err != nil {
					fatalf("read expected PID: %v", err)
				}
				expected, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
				if err != nil {
					fatalf("invalid expected PID")
				}
				if err := validateProcess(captured, expected, *argsToken); err != nil {
					fatalf("%v", err)
				}
				process = true
			}
			if *token == "" || strings.Contains(string(captured.GetPayload()), *token) {
				if *tlsMetadata {
					info := captured.GetTls()
					if info["version"] != "TLS 1.3" || info["cipher_suite"] == "" || len(info["ja3"]) != 32 || !strings.HasPrefix(info["ja4"], "t13") {
						fatalf("TLS handshake metadata missing or invalid")
					}
				}
				event = true
			}
		}
		if processLog && event && process {
			fmt.Printf("PROCESS_LOG=1 EVENT=1 FORMAT=%s METADATA=1\n", wantFormat.String())
			return
		}
	}
	fatalf("timed out: PROCESS_LOG=%v EVENT=%v", processLog, event)
}

func validateProcess(event *pb.Event, expected int64, requiredArg string) error {
	nameValid := event.GetPname() != "" && event.GetPname() != "decryptor"
	if expected <= 0 || event.GetPid() != expected || !nameValid {
		return fmt.Errorf("request process attribution mismatch: expected_pid=%d captured_pid=%d name_valid=%v", expected, event.GetPid(), nameValid)
	}
	if requiredArg != "" && (!bytes.Contains(event.GetProcessArgs(), []byte(requiredArg)) || event.GetProcessArgsTruncated()) {
		return fmt.Errorf("request process arguments are missing or truncated: bytes=%d truncated=%v", len(event.GetProcessArgs()), event.GetProcessArgsTruncated())
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

func validateEvent(event *pb.Event, wantFormat pb.CaptureFormat, sensitiveText bool) error {
	if event.GetTimestamp() == 0 {
		return fmt.Errorf("timestamp is zero")
	}
	if event.GetSequence() == 0 {
		return fmt.Errorf("sequence is zero")
	}
	if event.GetLength() == 0 || int(event.GetLength()) != len(event.GetPayload()) {
		return fmt.Errorf("length=%d payload=%d", event.GetLength(), len(event.GetPayload()))
	}
	if event.GetOriginalLength() < event.GetLength() {
		return fmt.Errorf("original_length=%d length=%d", event.GetOriginalLength(), event.GetLength())
	}
	wantSensitivity := pb.Sensitivity_SENSITIVITY_NORMAL
	if wantFormat != pb.CaptureFormat_CAPTURE_FORMAT_TEXT || sensitiveText {
		wantSensitivity = pb.Sensitivity_SENSITIVITY_SENSITIVE
	}
	if event.GetSensitivity() != wantSensitivity {
		return fmt.Errorf("sensitivity=%s want=%s", event.GetSensitivity(), wantSensitivity)
	}
	return nil
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
