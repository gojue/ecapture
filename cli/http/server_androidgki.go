//go:build androidgki
// +build androidgki

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

package http

func (hs *HttpServer) attach() {
	hs.ge.POST("/gnutls", hs.Gnutls)
	hs.ge.POST("/gotls", hs.Gotls)
	hs.ge.POST("/nss", hs.Nss)
	hs.ge.POST("/nspr", hs.Nss)
	hs.ge.POST("/tls", hs.Tls)
	hs.ge.POST("/openssl", hs.Tls)
	hs.ge.POST("/boringssl", hs.Tls)
}
