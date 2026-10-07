// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package openssl

import (
	"sync"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/output/writers"
)

type connectionInfo struct {
	tuple string
	sock  uint64
}

// connectionHandler owns OpenSSL's socket-to-FD state. Connection lifecycle
// events are internal module data and must never reach captured text output.
type connectionHandler struct {
	mu         sync.RWMutex
	byPIDAndFD map[uint32]map[uint32]connectionInfo
	bySocket   map[uint64][2]uint32
}

func newConnectionHandler() *connectionHandler {
	return &connectionHandler{
		byPIDAndFD: make(map[uint32]map[uint32]connectionInfo),
		bySocket:   make(map[uint64][2]uint32),
	}
}

func (h *connectionHandler) Supports(event domain.Event) bool {
	if event == nil || event.Type() != domain.EventTypeModuleData {
		return false
	}
	_, ok := event.(*ConnDataEvent)
	return ok
}

func (h *connectionHandler) Handle(event domain.Event) error {
	if !h.Supports(event) {
		return errors.New(errors.ErrCodeEventDispatch, "connection handler does not support event")
	}
	connEvent := event.(*ConnDataEvent)

	h.mu.Lock()
	defer h.mu.Unlock()
	if connEvent.IsDestroy != 0 {
		h.deleteBySocket(connEvent.Sock)
		return nil
	}
	if connEvent.Fd == 0 {
		return errors.New(errors.ErrCodeEventValidation, "connection event has zero file descriptor")
	}

	connections := h.byPIDAndFD[connEvent.Pid]
	if connections == nil {
		connections = make(map[uint32]connectionInfo)
		h.byPIDAndFD[connEvent.Pid] = connections
	}
	connections[connEvent.Fd] = connectionInfo{tuple: connEvent.Tuple, sock: connEvent.Sock}
	if connEvent.Sock != 0 {
		h.bySocket[connEvent.Sock] = [2]uint32{connEvent.Pid, connEvent.Fd}
	}
	return nil
}

func (h *connectionHandler) lookup(pid, fd uint32) (connectionInfo, bool) {
	if fd == 0 {
		return connectionInfo{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	connections := h.byPIDAndFD[pid]
	if connections == nil {
		return connectionInfo{}, false
	}
	info, ok := connections[fd]
	return info, ok
}

func (h *connectionHandler) deleteBySocket(sock uint64) {
	pidAndFD, ok := h.bySocket[sock]
	if !ok {
		return
	}
	delete(h.bySocket, sock)
	pid, fd := pidAndFD[0], pidAndFD[1]
	connections := h.byPIDAndFD[pid]
	info, ok := connections[fd]
	if !ok || info.sock != sock {
		return
	}
	delete(connections, fd)
	if len(connections) == 0 {
		delete(h.byPIDAndFD, pid)
	}
}

func (h *connectionHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byPIDAndFD = make(map[uint32]map[uint32]connectionInfo)
	h.bySocket = make(map[uint64][2]uint32)
	return nil
}

func (h *connectionHandler) Name() string {
	return "openssl-connection-state"
}

func (h *connectionHandler) Writer() writers.OutputWriter {
	return nil
}
