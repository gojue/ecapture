// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package har collects HTTP requests and responses and stores them in HAR format.
//
// For more information on HAR, see:
// https://w3c.github.io/web-performance/specs/HAR/Overview.html

// from https://github.com/google/martian

package har

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
)

var (
	ctxmu sync.RWMutex
	ctxs  = make(map[*http.Request]string)
)

// NewContext returns a context for the in-flight HTTP request.
func NewContext(req *http.Request) string {
	ctxmu.RLock()
	defer ctxmu.RUnlock()

	return ctxs[req]
}

// unlink removes the context for request.
func unlink(req *http.Request) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	delete(ctxs, req)
}

func genID() (string, error) {
	src := make([]byte, 8)
	if _, err := rand.Read(src); err != nil {
		return "", err
	}
	return hex.EncodeToString(src), nil
}

func TestContext(req *http.Request) (func(), error) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	_, ok := ctxs[req]
	if ok {
		return func() { unlink(req) }, nil
	}

	ctx, err := genID()
	if err != nil {
		return nil, err
	}
	ctxs[req] = ctx

	return func() { unlink(req) }, nil
}
