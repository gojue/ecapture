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

package ecaptureq

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var ErrBackpressure = errors.New("ecaptureq backpressure")

type publishRequest struct {
	message    []byte
	processLog bool
	result     chan error
}

type registerRequest struct {
	client *Client
	result chan error
}

// Hub serializes publish, history, and client registration so a new client gets
// a stable bounded history followed by live messages without a handoff race.
type Hub struct {
	ctx        context.Context
	broadcast  chan publishRequest
	register   chan registerRequest
	unregister chan *Client
	clients    map[*Client]struct{}
	history    [][]byte
	done       chan struct{}
	closeOnce  sync.Once
	dropped    atomic.Uint64
}

func newHub(ctx context.Context) *Hub {
	h := &Hub{
		ctx:        ctx,
		broadcast:  make(chan publishRequest, 256),
		register:   make(chan registerRequest, 32),
		unregister: make(chan *Client, 32),
		clients:    make(map[*Client]struct{}),
		history:    make([][]byte, 0, LogBuffLen),
		done:       make(chan struct{}),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	defer close(h.done)
	for {
		select {
		case <-h.ctx.Done():
			for client := range h.clients {
				delete(h.clients, client)
				close(client.send)
			}
			return
		case request := <-h.register:
			var err error
			for _, message := range h.history {
				select {
				case request.client.send <- append([]byte(nil), message...):
				default:
					err = fmt.Errorf("%w: startup history exceeds client queue", ErrBackpressure)
					h.dropped.Add(1)
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				h.clients[request.client] = struct{}{}
			}
			request.result <- err
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case request := <-h.broadcast:
			if request.processLog {
				h.appendHistory(request.message)
			}
			var deliveryErr error
			for client := range h.clients {
				select {
				case client.send <- append([]byte(nil), request.message...):
				default:
					delete(h.clients, client)
					close(client.send)
					h.dropped.Add(1)
					deliveryErr = fmt.Errorf("%w: client queue full", ErrBackpressure)
				}
			}
			request.result <- deliveryErr
		}
	}
}

func (h *Hub) appendHistory(message []byte) {
	copyMessage := append([]byte(nil), message...)
	if len(h.history) < LogBuffLen {
		h.history = append(h.history, copyMessage)
		return
	}
	copy(h.history, h.history[1:])
	h.history[len(h.history)-1] = copyMessage
}

func (h *Hub) publish(ctx context.Context, message []byte, processLog bool) error {
	request := publishRequest{
		message:    append([]byte(nil), message...),
		processLog: processLog,
		result:     make(chan error, 1),
	}
	select {
	case h.broadcast <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-h.ctx.Done():
		return context.Canceled
	default:
		h.dropped.Add(1)
		return fmt.Errorf("%w: publisher queue full", ErrBackpressure)
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-h.ctx.Done():
		return context.Canceled
	}
}

func (h *Hub) registerClient(ctx context.Context, client *Client) error {
	request := registerRequest{client: client, result: make(chan error, 1)}
	select {
	case h.register <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-h.ctx.Done():
		return context.Canceled
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-h.ctx.Done():
		return context.Canceled
	}
}

func (h *Hub) unregisterClient(client *Client) {
	select {
	case h.unregister <- client:
	case <-h.ctx.Done():
	}
}

func (h *Hub) wait() { <-h.done }

func (h *Hub) droppedCount() uint64 { return h.dropped.Load() }
