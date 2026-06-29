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
	"sync/atomic"

	"golang.org/x/sys/windows"

	"github.com/gojue/ecapture/internal/errors"
)

// HookCallback is the function type for hook entry/return callbacks.
// Args are the first few register-sized arguments captured at the hook site.
type HookCallback func(funcAddr uintptr, processId uint32, args []uintptr)

// Hook represents a single function hook.
type Hook struct {
	mu           sync.Mutex
	targetModule string
	targetFunc   string
	callback     HookCallback
	original     uintptr
	trampoline   uintptr
	hooked       bool
	moduleHandle windows.Handle
}

// HookConfig holds configuration for creating a hook.
type HookConfig struct {
	Module   string
	FuncName string
	Callback HookCallback
}

// NewHook creates a new function hook.
func NewHook(config HookConfig) (*Hook, error) {
	if config.Module == "" {
		return nil, errors.New(errors.ErrCodeConfiguration, "module name is required")
	}
	if config.FuncName == "" {
		return nil, errors.New(errors.ErrCodeConfiguration, "function name is required")
	}
	if config.Callback == nil {
		return nil, errors.New(errors.ErrCodeConfiguration, "callback is required")
	}
	return &Hook{
		targetModule: config.Module,
		targetFunc:   config.FuncName,
		callback:     config.Callback,
	}, nil
}

// Install resolves the target function address and activates the inline hook.
func (h *Hook) Install() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.hooked {
		return errors.New(errors.ErrCodeConfiguration, "hook already installed")
	}

	moduleHandle, err := loadModuleRef(h.targetModule)
	if err != nil {
		return errors.Wrap(errors.ErrCodeResourceNotFound, "load module", err).WithContext("module", h.targetModule)
	}

	addr, err := windows.GetProcAddress(moduleHandle, h.targetFunc)
	if err != nil {
		_ = freeModuleRef(h.targetModule)
		return errors.Wrap(errors.ErrCodeResourceNotFound, "resolve function", err).WithContext("module", h.targetModule).WithContext("function", h.targetFunc)
	}

	h.original = uintptr(addr)
	trampoline, err := createTrampoline(h, h.original)
	if err != nil {
		_ = freeModuleRef(h.targetModule)
		return errors.Wrap(errors.ErrCodeResourceAllocation, "create trampoline", err).WithContext("module", h.targetModule).WithContext("function", h.targetFunc)
	}

	h.trampoline = trampoline
	h.moduleHandle = moduleHandle
	h.hooked = true
	return nil
}

// Remove deactivates the hook and releases resources.
func (h *Hook) Remove() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.hooked {
		return
	}
	if h.trampoline != 0 {
		_ = releaseTrampoline(h.original, h.trampoline)
	}
	if h.targetModule != "" {
		_ = freeModuleRef(h.targetModule)
	}
	h.hooked = false
	h.original = 0
	h.trampoline = 0
	h.moduleHandle = 0
}

// IsHooked returns whether the hook is active.
func (h *Hook) IsHooked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hooked
}

// OriginalFunc returns the resolved original function address.
func (h *Hook) OriginalFunc() uintptr {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.original
}

// Trampoline returns the address of the trampoline that invokes the original function.
func (h *Hook) Trampoline() uintptr {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.trampoline
}

// InvokeOriginal calls the original function through the trampoline.
func (h *Hook) InvokeOriginal(args ...uintptr) uintptr {
	h.mu.Lock()
	trampoline := h.trampoline
	h.mu.Unlock()
	if trampoline == 0 {
		return 0
	}
	return invokeTrampoline(trampoline, args)
}

// HookManager manages multiple hooks.
type HookManager struct {
	mu     sync.Mutex
	hooks  map[string]*Hook
	closed atomic.Bool
}

// NewHookManager creates a new hook manager.
func NewHookManager() *HookManager {
	return &HookManager{hooks: make(map[string]*Hook)}
}

// AddHook creates and installs a new hook.
func (m *HookManager) AddHook(name string, config HookConfig) error {
	if m.closed.Load() {
		return errors.New(errors.ErrCodeResourceCleanup, "hook manager is closed")
	}

	m.mu.Lock()
	if _, exists := m.hooks[name]; exists {
		m.mu.Unlock()
		return errors.New(errors.ErrCodeConfiguration, "hook already exists").WithContext("name", name)
	}
	m.mu.Unlock()

	h, err := NewHook(config)
	if err != nil {
		return err
	}
	if err := h.Install(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		h.Remove()
		return errors.New(errors.ErrCodeResourceCleanup, "hook manager is closed")
	}
	if _, exists := m.hooks[name]; exists {
		h.Remove()
		return errors.New(errors.ErrCodeConfiguration, "hook already exists").WithContext("name", name)
	}
	m.hooks[name] = h
	return nil
}

// Remove removes a single hook by name.
func (m *HookManager) Remove(name string) bool {
	m.mu.Lock()
	h, ok := m.hooks[name]
	if ok {
		delete(m.hooks, name)
	}
	m.mu.Unlock()
	if h != nil {
		h.Remove()
	}
	return ok
}

// RemoveAll removes all hooks.
func (m *HookManager) RemoveAll() {
	m.mu.Lock()
	hooks := make([]*Hook, 0, len(m.hooks))
	for _, h := range m.hooks {
		hooks = append(hooks, h)
	}
	m.hooks = make(map[string]*Hook)
	m.mu.Unlock()

	for _, h := range hooks {
		h.Remove()
	}
}

// Close removes all hooks and marks the manager as closed.
func (m *HookManager) Close() error {
	m.closed.Store(true)
	m.RemoveAll()
	return nil
}

// GetHook returns a specific hook by name.
func (m *HookManager) GetHook(name string) (*Hook, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hooks[name]
	return h, ok
}

// moduleRefCount tracks loaded modules to avoid leaking handles.
var (
	moduleMu    sync.Mutex
	moduleRefs  = make(map[string]windows.Handle)
	moduleCount = make(map[string]int)
)

func loadModuleRef(moduleName string) (windows.Handle, error) {
	moduleMu.Lock()
	defer moduleMu.Unlock()

	if handle, ok := moduleRefs[moduleName]; ok {
		moduleCount[moduleName]++
		return handle, nil
	}

	handle, err := windows.LoadLibrary(moduleName)
	if err != nil {
		return 0, err
	}
	moduleRefs[moduleName] = handle
	moduleCount[moduleName] = 1
	return handle, nil
}

func freeModuleRef(moduleName string) error {
	moduleMu.Lock()
	defer moduleMu.Unlock()

	count := moduleCount[moduleName]
	if count <= 1 {
		if handle, ok := moduleRefs[moduleName]; ok {
			_ = windows.FreeLibrary(handle)
		}
		delete(moduleRefs, moduleName)
		delete(moduleCount, moduleName)
		return nil
	}
	moduleCount[moduleName] = count - 1
	return nil
}

// ResolveFuncAddr resolves a function address in a loaded module.
// The module handle is kept alive via reference counting so the returned
// address remains valid for the lifetime of the process.
func ResolveFuncAddr(moduleName, funcName string) (uintptr, error) {
	handle, err := loadModuleRef(moduleName)
	if err != nil {
		return 0, err
	}

	addr, err := windows.GetProcAddress(handle, funcName)
	if err != nil {
		_ = freeModuleRef(moduleName)
		return 0, err
	}
	return uintptr(addr), nil
}
