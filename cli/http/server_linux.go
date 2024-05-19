//go:build !androidgki
// +build !androidgki

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

import (
	"github.com/gin-gonic/gin"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
)

func (hs *HttpServer) attach() {
	hs.ge.POST("/bash", hs.Bash)
	hs.ge.POST("/gnutls", hs.Gnutls)
	hs.ge.POST("/gotls", hs.Gotls)
	hs.ge.POST("/mysqld", hs.Mysqld)
	hs.ge.POST("/nss", hs.Nss)
	hs.ge.POST("/nspr", hs.Nss)
	hs.ge.POST("/postgress", hs.Postgress)
	hs.ge.POST("/tls", hs.Tls)
	hs.ge.POST("/openssl", hs.Tls)
	hs.ge.POST("/boringssl", hs.Tls)
}

func (hs *HttpServer) Bash(c *gin.Context) {
	hs.decodeConf(new(config.BashConfig), c, module.ModuleNameBash)
	return
}

func (hs *HttpServer) Mysqld(c *gin.Context) {
	hs.decodeConf(new(config.MysqldConfig), c, module.ModuleNameMysqld)
	return
}

func (hs *HttpServer) Postgress(c *gin.Context) {
	hs.decodeConf(new(config.PostgresConfig), c, module.ModuleNamePostgres)
	return
}
