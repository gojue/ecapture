// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package errors

import (
	"fmt"
)

// ErrorCode defines standardized error codes for eCapture.
type ErrorCode int

const (
	// ErrCodeUnknown represents an unknown error.
	ErrCodeUnknown ErrorCode = iota

	// Configuration errors (1xx)
	ErrCodeConfiguration ErrorCode = 101
	ErrCodeConfigValidation
	ErrCodeConfigMissing

	// Probe lifecycle errors (2xx)
	ErrCodeProbeInit ErrorCode = 201
	ErrCodeProbeStart
	ErrCodeProbeStop
	ErrCodeProbeClose

	// Event processing errors (3xx)
	ErrCodeEventDecode ErrorCode = 301
	ErrCodeEventDispatch
	ErrCodeEventValidation
	ErrCodeEventNotReady

	// eBPF errors (4xx)
	ErrCodeEBPFLoad ErrorCode = 401
	ErrCodeEBPFAttach
	ErrCodeEBPFMapAccess

	// Resource errors (5xx)
	ErrCodeResourceNotFound ErrorCode = 501
	ErrCodeResourceAllocation
	ErrCodeResourceCleanup
)

// Error represents a structured error in eCapture.
type Error struct {
	Code    ErrorCode
	Message string
	Cause   error
	Context map[string]any
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Cause
}

// WithContext adds contextual information to the error.
func (e *Error) WithContext(key string, value any) *Error {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// New creates a new Error with the given code and message.
func New(code ErrorCode, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Context: make(map[string]any),
	}
}

// Wrap wraps an existing error with additional context.
func Wrap(code ErrorCode, message string, cause error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   cause,
		Context: make(map[string]any),
	}
}

var ErrEventNotReady = New(ErrCodeEventNotReady, "event not ready yet")

// NewConfigurationError creates a configuration error.
func NewConfigurationError(message string, cause error) *Error {
	return Wrap(ErrCodeConfiguration, message, cause)
}

// NewProbeInitError creates a probe initialization error.
func NewProbeInitError(probeName string, cause error) *Error {
	return Wrap(ErrCodeProbeInit, fmt.Sprintf("failed to initialize probe '%s'", probeName), cause)
}

// NewProbeStartError creates a probe start error.
func NewProbeStartError(probeName string, cause error) *Error {
	return Wrap(ErrCodeProbeStart, fmt.Sprintf("failed to start probe '%s'", probeName), cause)
}

// NewProbeStopError creates a probe stop error.
func NewProbeStopError(probeName string, cause error) *Error {
	return Wrap(ErrCodeProbeStop, fmt.Sprintf("failed to stop probe '%s'", probeName), cause)
}

// NewProbeCloseError creates a probe close error.
func NewProbeCloseError(probeName string, cause error) *Error {
	return Wrap(ErrCodeProbeClose, fmt.Sprintf("failed to close probe '%s'", probeName), cause)
}

// NewEventDecodeError creates an event decode error.
func NewEventDecodeError(eventType string, cause error) *Error {
	return Wrap(ErrCodeEventDecode, fmt.Sprintf("failed to decode event of type '%s'", eventType), cause)
}

// NewEventDispatchError creates an event dispatch error.
func NewEventDispatchError(cause error) *Error {
	return Wrap(ErrCodeEventDispatch, "failed to dispatch event", cause)
}

// NewEBPFLoadError creates an eBPF load error.
func NewEBPFLoadError(program string, cause error) *Error {
	return Wrap(ErrCodeEBPFLoad, fmt.Sprintf("failed to load eBPF program '%s'", program), cause)
}

// NewEBPFAttachError creates an eBPF attach error.
func NewEBPFAttachError(probe string, cause error) *Error {
	return Wrap(ErrCodeEBPFAttach, fmt.Sprintf("failed to attach eBPF probe '%s'", probe), cause)
}

// NewResourceNotFoundError creates a resource not found error.
func NewResourceNotFoundError(resource string) *Error {
	return New(ErrCodeResourceNotFound, fmt.Sprintf("resource not found: %s", resource))
}
