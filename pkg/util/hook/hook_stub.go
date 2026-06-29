//go:build !windows
// +build !windows

package hook

import "github.com/gojue/ecapture/internal/errors"

// HookCallback is the function type for hook callbacks.
type HookCallback func(funcAddr uintptr, processId uint32, args []uintptr)

// Hook represents a single function hook (stub on non-Windows).
type Hook struct{}

// HookConfig holds configuration for creating a hook.
type HookConfig struct {
	Module   string
	FuncName string
	Callback HookCallback
}

func NewHook(_ HookConfig) (*Hook, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "hook is only supported on Windows")
}
func (h *Hook) Install() error {
	return errors.New(errors.ErrCodeConfiguration, "hook is only supported on Windows")
}
func (h *Hook) Remove()               {}
func (h *Hook) IsHooked() bool        { return false }
func (h *Hook) OriginalFunc() uintptr { return 0 }

// HookManager manages hooks (stub on non-Windows).
type HookManager struct{}

func NewHookManager() *HookManager { return &HookManager{} }
func (m *HookManager) AddHook(_ string, _ HookConfig) error {
	return errors.New(errors.ErrCodeConfiguration, "hook is only supported on Windows")
}
func (m *HookManager) Remove(_ string) bool           { return false }
func (m *HookManager) RemoveAll()                     {}
func (m *HookManager) Close() error                   { return nil }
func (m *HookManager) GetHook(_ string) (*Hook, bool) { return nil, false }

// ResolveFuncAddr is a stub on non-Windows.
func ResolveFuncAddr(_, _ string) (uintptr, error) {
	return 0, errors.New(errors.ErrCodeConfiguration, "ResolveFuncAddr is only supported on Windows")
}
