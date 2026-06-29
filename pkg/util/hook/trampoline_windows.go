//go:build windows
// +build windows

// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package hook

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gojue/ecapture/internal/errors"
)

const (
	pageExecuteReadWrite = 0x40
	memCommit            = 0x1000
	memReserve           = 0x2000
)

// trampolineState holds runtime data for an installed hook.
type trampolineState struct {
	callback   uintptr
	cbAddr     uintptr
	targetAddr uintptr
	trampoline uintptr
	origBytes  []byte
	hook       *Hook
}

var (
	trampolineMu  sync.Mutex
	trampolineMap = make(map[uintptr]*trampolineState)
)

// createTrampoline installs an inline hook at targetAddr and returns the
// trampoline address used to call the original function.
func createTrampoline(h *Hook, targetAddr uintptr) (uintptr, error) {
	if targetAddr == 0 {
		return 0, errors.New(errors.ErrCodeResourceAllocation, "target address is zero")
	}

	hookLen, err := minHookLength(targetAddr)
	if err != nil {
		return 0, err
	}

	origBytes := make([]byte, hookLen)
	src := (*[1 << 30]byte)(unsafe.Pointer(targetAddr))
	copy(origBytes, src[:hookLen:hookLen])

	// Allocate executable memory for the trampoline.
	trampoline, err := virtualAlloc(uintptr(hookLen) + 14)
	if err != nil {
		return 0, errors.Wrap(errors.ErrCodeResourceAllocation, "allocate trampoline memory", err)
	}

	dst := (*[1 << 30]byte)(unsafe.Pointer(trampoline))
	offset := 0

	// Copy original instructions to trampoline.
	copy(dst[offset:], origBytes)
	offset += hookLen

	// Append absolute jump back to original code (targetAddr + hookLen).
	writeAbsoluteJump(dst[offset:offset+12], targetAddr+uintptr(hookLen))
	offset += 12

	// Make trampoline executable (already RWX from allocation).
	_ = flushInstructionCache(trampoline, uintptr(offset))

	// Create the callback thunk.
	cb := syscall.NewCallback(func(a, b, c, d, e, f uintptr) uintptr {
		if h.callback != nil {
			h.callback(h.original, uint32(windows.GetCurrentProcessId()), []uintptr{a, b, c, d, e, f})
		}
		return invokeTrampoline(h.trampoline, []uintptr{a, b, c, d, e, f})
	})

	state := &trampolineState{
		callback:   cb,
		cbAddr:     cb,
		targetAddr: targetAddr,
		trampoline: trampoline,
		origBytes:  origBytes,
		hook:       h,
	}

	// Set the trampoline on the hook before activation so the callback can
	// safely invoke it without racing against the assignment in Install.
	h.trampoline = trampoline

	if err := activateHook(state.targetAddr, state.cbAddr, origBytes); err != nil {
		_ = virtualFree(trampoline)
		return 0, errors.Wrap(errors.ErrCodeResourceAllocation, "activate hook", err)
	}

	trampolineMu.Lock()
	trampolineMap[targetAddr] = state
	trampolineMu.Unlock()

	return trampoline, nil
}

// activateHook writes the inline jump from targetAddr to the callback thunk.
func activateHook(targetAddr, callbackAddr uintptr, origBytes []byte) error {
	hookLen := len(origBytes)
	oldProtect, err := setMemoryProtection(targetAddr, uintptr(hookLen), pageExecuteReadWrite)
	if err != nil {
		return errors.Wrap(errors.ErrCodeResourceAllocation, "change memory protection", err)
	}
	defer func() {
		_, _ = setMemoryProtection(targetAddr, uintptr(hookLen), oldProtect)
	}()

	dst := (*[1 << 30]byte)(unsafe.Pointer(targetAddr))
	// Use an absolute jump so we do not depend on the callback being within 2 GB.
	writeAbsoluteJump(dst[:], callbackAddr)

	// Fill remaining bytes with NOPs if hookLen > 12.
	for i := 12; i < hookLen; i++ {
		dst[i] = 0x90
	}

	_ = flushInstructionCache(targetAddr, uintptr(hookLen))
	return nil
}

// deactivateHook restores the original bytes at targetAddr.
func deactivateHook(targetAddr uintptr, origBytes []byte) error {
	if len(origBytes) == 0 {
		return nil
	}
	oldProtect, err := setMemoryProtection(targetAddr, uintptr(len(origBytes)), pageExecuteReadWrite)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = setMemoryProtection(targetAddr, uintptr(len(origBytes)), oldProtect)
	}()

	dst := (*[1 << 30]byte)(unsafe.Pointer(targetAddr))
	copy(dst[:len(origBytes)], origBytes)
	_ = flushInstructionCache(targetAddr, uintptr(len(origBytes)))
	return nil
}

// releaseTrampoline removes the hook and frees the trampoline memory.
func releaseTrampoline(targetAddr, trampolineAddr uintptr) error {
	trampolineMu.Lock()
	state, ok := trampolineMap[targetAddr]
	delete(trampolineMap, targetAddr)
	trampolineMu.Unlock()

	if ok && state != nil {
		_ = deactivateHook(targetAddr, state.origBytes)
		// Windows syscall.NewCallback returns a runtime-managed thunk;
		// there is no explicit free API on this platform.
	}

	if trampolineAddr != 0 {
		_ = virtualFree(trampolineAddr)
	}
	return nil
}

// invokeTrampoline calls the original function through the trampoline using
// the Windows x64 calling convention via syscall.Syscall6.
func invokeTrampoline(trampolineAddr uintptr, args []uintptr) uintptr {
	if trampolineAddr == 0 {
		return 0
	}
	nargs := uintptr(len(args))
	var a1, a2, a3, a4, a5, a6 uintptr
	switch len(args) {
	case 6:
		a6 = args[5]
		fallthrough
	case 5:
		a5 = args[4]
		fallthrough
	case 4:
		a4 = args[3]
		fallthrough
	case 3:
		a3 = args[2]
		fallthrough
	case 2:
		a2 = args[1]
		fallthrough
	case 1:
		a1 = args[0]
	}
	r1, _, _ := syscall.Syscall6(trampolineAddr, nargs, a1, a2, a3, a4, a5, a6)
	return r1
}

// writeAbsoluteJump writes a 12-byte absolute jump to destAddr at p.
// mov rax, <addr>  (48 B8 <8 bytes>)
// jmp rax          (FF E0)
func writeAbsoluteJump(p []byte, destAddr uintptr) {
	p[0] = 0x48
	p[1] = 0xB8
	*(*uintptr)(unsafe.Pointer(&p[2])) = destAddr
	p[10] = 0xFF
	p[11] = 0xE0
}

// minHookLength returns the number of bytes that must be copied to the
// trampoline so that the original instructions can be safely overwritten
// with a 12-byte absolute jump.
func minHookLength(addr uintptr) (int, error) {
	const maxScan = 32
	length := 0
	for length < 12 && length < maxScan {
		ilen, err := instructionLength(addr + uintptr(length))
		if err != nil {
			return 0, err
		}
		if ilen == 0 {
			return 0, errors.New(errors.ErrCodeUnknown, "unrecognized instruction")
		}
		length += ilen
	}
	if length < 12 {
		return 0, errors.New(errors.ErrCodeUnknown, "could not find 12 bytes of safe instructions to overwrite")
	}
	return length, nil
}

// instructionLength returns the length of the x86-64 instruction at addr.
// This is a minimal decoder sufficient for common function prologues.
func instructionLength(addr uintptr) (int, error) {
	p := (*[1 << 30]byte)(unsafe.Pointer(addr))
	b := p[0]

	// Single-byte instructions that do not have operands affecting length.
	switch b {
	case 0x90, 0xC3, 0xCC:
		return 1, nil
	}

	pos := 0
	hasREX := false
	rexB := false
	rexX := false
	rexR := false
	operandSize := 4 // 4 = 32-bit default; 8 = 64-bit with REX.W; 2 = 16-bit with 0x66

	// Parse prefixes.
	for {
		if b >= 0x40 && b <= 0x4F {
			hasREX = true
			rexB = b&0x01 != 0
			rexX = b&0x02 != 0
			rexR = b&0x04 != 0
			if b&0x08 != 0 {
				operandSize = 8
			}
			pos++
			b = p[pos]
			continue
		}
		if b == 0x66 {
			operandSize = 2
			pos++
			b = p[pos]
			continue
		}
		if b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 {
			pos++
			b = p[pos]
			continue
		}
		break
	}

	// Two-byte opcode.
	if b == 0x0F {
		op2 := p[pos+1]
		switch op2 {
		case 0x10, 0x11, 0x28, 0x29, 0x2E, 0x2F, 0x38, 0x39, 0x3A, 0x3B, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0xB6, 0xB7, 0xBE, 0xBF:
			return pos + 2 + modRMLength(p[pos+2], hasREX, rexB, rexX, rexR, operandSize), nil
		}
		return 0, errors.New(errors.ErrCodeUnknown, "unsupported two-byte opcode")
	}

	// Common one-byte opcodes.
	switch {
	case b >= 0x50 && b <= 0x57: // PUSH reg
		return pos + 1, nil
	case b >= 0x58 && b <= 0x5F: // POP reg
		return pos + 1, nil
	case b >= 0xB0 && b <= 0xB7: // MOV r8, imm8
		return pos + 2, nil
	case b >= 0xB8 && b <= 0xBF: // MOV r16/r32/r64, imm
		width := operandSize
		if width == 4 {
			width = 4
		} else if width == 2 {
			width = 2
		} else if width == 8 {
			width = 8
		}
		return pos + 1 + width, nil
	case b >= 0x88 && b <= 0x8C: // MOV/LEA group
		return pos + 1 + modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize), nil
	case b >= 0x80 && b <= 0x83: // ALU with immediate
		modLen := modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize)
		immSize := 1
		if b == 0x81 {
			immSize = operandSize
			if immSize == 2 {
				immSize = 2
			} else {
				immSize = 4
			}
		}
		return pos + 1 + modLen + immSize, nil
	case b >= 0x84 && b <= 0x86: // TEST/XCHG reg, r/m
		return pos + 1 + modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize), nil
	case b >= 0x89 && b <= 0x8B: // MOV r/m, reg / MOV reg, r/m
		return pos + 1 + modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize), nil
	case b >= 0x8D: // LEA
		return pos + 1 + modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize), nil
	case b >= 0xC6 && b <= 0xC7: // MOV r/m, imm
		modLen := modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize)
		immSize := 1
		if b == 0xC7 {
			immSize = operandSize
			if immSize == 2 {
				immSize = 2
			} else {
				immSize = 4
			}
		}
		return pos + 1 + modLen + immSize, nil
	case b == 0xE8 || b == 0xE9: // CALL/JMP rel32
		return pos + 5, nil
	case b == 0xEB: // JMP rel8
		return pos + 2, nil
	case b == 0xFF: // INC/DEC/CALL/JMP group
		return pos + 1 + modRMLength(p[pos+1], hasREX, rexB, rexX, rexR, operandSize), nil
	}

	return 0, errors.New(errors.ErrCodeUnknown, "unsupported instruction byte")
}

// modRMLength returns the length of the ModR/M byte plus SIB and displacement.
func modRMLength(modrm byte, hasREX, rexB, rexX, rexR bool, operandSize int) int {
	mod := (modrm >> 6) & 0x3
	rm := modrm & 0x7

	length := 1

	if mod != 3 && rm == 4 {
		// SIB byte present.
		length++
	}

	dispSize := 0
	if mod == 1 {
		dispSize = 1
	} else if mod == 2 {
		dispSize = 4
	} else if mod == 0 && rm == 5 {
		dispSize = 4
	}

	_ = hasREX
	_ = rexB
	_ = rexX
	_ = rexR
	_ = operandSize

	return length + dispSize
}

func virtualAlloc(size uintptr) (uintptr, error) {
	addr, err := windows.VirtualAlloc(0, size, memCommit|memReserve, pageExecuteReadWrite)
	if err != nil {
		return 0, err
	}
	return addr, nil
}

func virtualFree(addr uintptr) error {
	return windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

func setMemoryProtection(addr, size uintptr, prot uint32) (uint32, error) {
	var oldProtect uint32
	err := windows.VirtualProtect(addr, size, prot, &oldProtect)
	return oldProtect, err
}

var kernel32 = windows.NewLazyDLL("kernel32.dll")

func flushInstructionCache(addr, size uintptr) error {
	h := windows.CurrentProcess()
	proc := kernel32.NewProc("FlushInstructionCache")
	ret, _, err := proc.Call(uintptr(h), addr, size)
	if ret == 0 {
		return err
	}
	return nil
}
