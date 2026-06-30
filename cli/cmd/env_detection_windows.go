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

package cmd

import (
	"runtime"

	"golang.org/x/sys/windows"

	"github.com/gojue/ecapture/internal/errors"
)

func detectKernel() error {
	// On Windows, we check the OS version instead of kernel version.
	// eCapture for Windows requires Windows 10 version 1809+ (build 17763+)
	// for ETW Schannel provider support and modern TLS features.
	ver := windows.RtlGetVersion()
	if ver == nil {
		return errors.New(errors.ErrCodeConfiguration, "failed to get Windows version")
	}

	// Windows 10 = MajorVersion 10, MinorVersion 0
	if ver.MajorVersion < 10 {
		return errors.New(errors.ErrCodeConfiguration, "Windows version is not supported. Requires Windows 10 (build 17763) or later").
			WithContext("major", ver.MajorVersion).
			WithContext("minor", ver.MinorVersion)
	}

	// Build 17763 = Windows 10 version 1809 (October 2018 Update)
	if ver.BuildNumber < 17763 {
		return errors.New(errors.ErrCodeConfiguration, "Windows 10 build is not supported. Requires build 17763 (version 1809) or later").
			WithContext("build", ver.BuildNumber)
	}

	return nil
}

func detectBpfCap() error {
	// On Windows, we check for administrator privileges instead of CAP_BPF.
	// ETW sessions and function hooking require elevated privileges.
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "failed to check administrator privileges", err)
	}
	defer windows.FreeSid(sid)

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "failed to open process token", err)
	}
	defer token.Close()

	member, err := token.IsMember(sid)
	if err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "failed to check administrator group membership", err)
	}

	if !member {
		return errors.New(errors.ErrCodeConfiguration, "eCapture on Windows requires administrator privileges. Please run as Administrator")
	}

	// Check architecture
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New(errors.ErrCodeConfiguration, "unsupported CPU architecture. Only amd64 and arm64 are supported").
			WithContext("arch", runtime.GOARCH)
	}

	return nil
}

func detectEnv() error {
	if err := detectKernel(); err != nil {
		return err
	}

	if err := detectBpfCap(); err != nil {
		return err
	}

	return nil
}
