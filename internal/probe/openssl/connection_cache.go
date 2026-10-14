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
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const connectionDestroyDelay = 3 * time.Second

type connectionKey struct {
	pid uint32
	fd  uint32
}

type connectionInfo struct {
	tuple           string
	sock            uint64
	sourceIP        string
	destinationIP   string
	sourcePort      uint16
	destinationPort uint16
	generation      uint64
}

// connectionCache joins OpenSSL connection records with TLS data records.
// The two perf maps have independent readers, so all accesses are synchronized.
type connectionCache struct {
	mu             sync.RWMutex
	byPID          map[uint32]map[uint32]connectionInfo
	bySock         map[uint64]connectionKey
	nextGeneration uint64
}

func (c *connectionCache) observe(event *ConnDataEvent) {
	if event.IsDestroy != 0 {
		c.expireLater(event.Sock)
		return
	}
	if event.Fd == 0 || event.Sock == 0 ||
		(event.Family != unix.AF_INET && event.Family != unix.AF_INET6) {
		return
	}

	var source, destination netip.Addr
	if event.Family == unix.AF_INET {
		source = netip.AddrFrom4([4]byte(event.Saddr[:4]))
		destination = netip.AddrFrom4([4]byte(event.Daddr[:4]))
	} else {
		source = netip.AddrFrom16(event.Saddr)
		destination = netip.AddrFrom16(event.Daddr)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byPID == nil {
		c.byPID = make(map[uint32]map[uint32]connectionInfo)
		c.bySock = make(map[uint64]connectionKey)
	}
	if c.byPID[event.Pid] == nil {
		c.byPID[event.Pid] = make(map[uint32]connectionInfo)
	}
	if previous, ok := c.byPID[event.Pid][event.Fd]; ok {
		delete(c.bySock, previous.sock)
	}
	if previousKey, ok := c.bySock[event.Sock]; ok {
		c.removeLocked(previousKey, event.Sock)
	}
	c.nextGeneration++
	c.byPID[event.Pid][event.Fd] = connectionInfo{
		tuple:           event.Tuple,
		sock:            event.Sock,
		sourceIP:        source.String(),
		destinationIP:   destination.String(),
		sourcePort:      event.Sport,
		destinationPort: event.Dport,
		generation:      c.nextGeneration,
	}
	c.bySock[event.Sock] = connectionKey{pid: event.Pid, fd: event.Fd}
}

func (c *connectionCache) lookup(pid, fd uint32) (connectionInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.byPID[pid][fd]
	return info, ok
}

func (c *connectionCache) expireLater(sock uint64) {
	c.mu.RLock()
	key, ok := c.bySock[sock]
	info := c.byPID[key.pid][key.fd]
	c.mu.RUnlock()
	if !ok {
		return
	}
	time.AfterFunc(connectionDestroyDelay, func() {
		c.expire(sock, info.generation)
	})
}

func (c *connectionCache) expire(sock, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ok := c.bySock[sock]
	if !ok {
		return
	}
	if info, ok := c.byPID[key.pid][key.fd]; ok && info.generation == generation {
		c.removeLocked(key, sock)
	}
}

func (c *connectionCache) removeLocked(key connectionKey, sock uint64) {
	delete(c.bySock, sock)
	if c.byPID[key.pid][key.fd].sock != sock {
		return
	}
	delete(c.byPID[key.pid], key.fd)
	if len(c.byPID[key.pid]) == 0 {
		delete(c.byPID, key.pid)
	}
}
