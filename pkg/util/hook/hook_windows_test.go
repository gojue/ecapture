//go:build windows
// +build windows

package hook

import (
	"testing"
)

func TestNewHookValidation(t *testing.T) {
	cases := []struct {
		name    string
		config  HookConfig
		wantErr bool
	}{
		{"missing module", HookConfig{FuncName: "Test", Callback: func(_ uintptr, _ uint32, _ []uintptr) {}}, true},
		{"missing function", HookConfig{Module: "kernel32.dll", Callback: func(_ uintptr, _ uint32, _ []uintptr) {}}, true},
		{"missing callback", HookConfig{Module: "kernel32.dll", FuncName: "Test"}, true},
		{"valid config", HookConfig{Module: "kernel32.dll", FuncName: "GetProcAddress", Callback: func(_ uintptr, _ uint32, _ []uintptr) {}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewHook(c.config)
			if (err != nil) != c.wantErr {
				t.Errorf("NewHook() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestHookManagerClosed(t *testing.T) {
	m := NewHookManager()
	if err := m.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := m.AddHook("test", HookConfig{
		Module:   "kernel32.dll",
		FuncName: "GetProcAddress",
		Callback: func(_ uintptr, _ uint32, _ []uintptr) {},
	}); err == nil {
		t.Error("AddHook on closed manager should return an error")
	}
}

func TestResolveFuncAddrKernel32(t *testing.T) {
	addr, err := ResolveFuncAddr("kernel32.dll", "GetProcAddress")
	if err != nil {
		t.Fatalf("ResolveFuncAddr error = %v", err)
	}
	if addr == 0 {
		t.Error("ResolveFuncAddr returned zero address for a known export")
	}
}
