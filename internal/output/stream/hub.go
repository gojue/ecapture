// Copyright 2025 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package stream

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var ErrBackpressure = errors.New("stream subscription backpressure")

// Hub serializes registration, history and complete-message delivery. Queues
// are bounded; only this owner closes a client's send channel.
type Hub struct {
	ctx           context.Context
	mu            sync.Mutex
	clients       map[*Client]struct{}
	history       [][]byte
	collectorInfo []byte
	closed        bool
	done          chan struct{}
	dropped       atomic.Uint64
}

func newHub(ctx context.Context) *Hub {
	h := &Hub{ctx: ctx, clients: make(map[*Client]struct{}), history: make([][]byte, 0, LogBuffLen), done: make(chan struct{})}
	go func() {
		<-ctx.Done()
		h.mu.Lock()
		h.closed = true
		for client := range h.clients {
			delete(h.clients, client)
			close(client.send)
		}
		h.mu.Unlock()
		close(h.done)
	}()
	return h
}

func (h *Hub) publish(ctx context.Context, message []byte, processLog, collectorInfo bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return context.Canceled
	}
	if collectorInfo {
		h.collectorInfo = append([]byte(nil), message...)
	} else if processLog {
		copyMessage := append([]byte(nil), message...)
		if len(h.history) < LogBuffLen {
			h.history = append(h.history, copyMessage)
		} else {
			copy(h.history, h.history[1:])
			h.history[len(h.history)-1] = copyMessage
		}
	}
	var deliveryErr error
	for client := range h.clients {
		if err := h.deliver(client, message); err != nil {
			deliveryErr = err
		}
	}
	return deliveryErr
}

// target is used by a subscriber's own pcapng encoder. Other subscribers must
// never receive its headers or packet stream.
func (h *Hub) target(ctx context.Context, client *Client, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return context.Canceled
	}
	if _, ok := h.clients[client]; !ok {
		return errClosedSubscriber
	}
	return h.deliver(client, message)
}

var errClosedSubscriber = errors.New("stream subscriber is closed")

func (h *Hub) deliver(client *Client, message []byte) error {
	select {
	case client.send <- append([]byte(nil), message...):
		return nil
	default:
		delete(h.clients, client)
		close(client.send)
		h.dropped.Add(1)
		return fmt.Errorf("%w: client queue full", ErrBackpressure)
	}
}

func (h *Hub) registerClient(ctx context.Context, client *Client) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return context.Canceled
	}
	if len(h.clients) >= maxClients {
		return fmt.Errorf("%w: subscriber limit reached", ErrBackpressure)
	}
	count := len(h.history)
	if h.collectorInfo != nil {
		count++
	}
	if count > cap(client.send) {
		h.dropped.Add(1)
		return fmt.Errorf("%w: startup history exceeds client queue", ErrBackpressure)
	}
	if h.collectorInfo != nil {
		client.send <- append([]byte(nil), h.collectorInfo...)
	}
	for _, message := range h.history {
		client.send <- append([]byte(nil), message...)
	}
	h.clients[client] = struct{}{}
	return nil
}

func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
	}
}

// drainClients detaches a generation after every encoder has flushed. Writer
// pumps consume the remaining queue before sending a normal close frame.
func (h *Hub) drainClients() []*Client {
	h.mu.Lock()
	defer h.mu.Unlock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		delete(h.clients, client)
		client.graceful.Store(!client.failed.Load())
		close(client.send)
		clients = append(clients, client)
	}
	return clients
}

func (h *Hub) wait()                { <-h.done }
func (h *Hub) droppedCount() uint64 { return h.dropped.Load() }
