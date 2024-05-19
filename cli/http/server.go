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
	"github.com/rs/zerolog"
	"net/http"
)

type HttpServer struct {
	//
	loadTime   int64       // 加载时间，防止短时间内多次加载
	loadStat   int8        // 加载状态，重启完成后，进行再次加载
	ModuleType string      //当前加载模块
	modConfig  interface{} //模块配置
	confChan   chan config.IConfig
	ge         *gin.Engine
	addr       string
	logger     zerolog.Logger
}

func NewHttpServer(addr string, confChan chan config.IConfig, zerologger zerolog.Logger) *HttpServer {
	gin.SetMode(gin.ReleaseMode)
	var errLogger = &ErrLogger{zerologger: zerologger}
	var infoLogger = &InfoLogger{zerologger: zerologger}
	gin.DefaultWriter = infoLogger
	gin.DefaultErrorWriter = errLogger
	r := gin.Default()
	r.Use(gin.Recovery())
	hs := &HttpServer{
		confChan: confChan,
		ge:       r,
		addr:     addr,
		logger:   zerologger,
	}
	hs.attach()
	return hs
}

func (hs HttpServer) Run() error {
	return hs.ge.Run(hs.addr)
}

func (hs *HttpServer) Tls(c *gin.Context) {
	hs.decodeConf(new(config.OpensslConfig), c, module.ModuleNameOpenssl)
	return
}

func (hs *HttpServer) Gnutls(c *gin.Context) {
	hs.decodeConf(new(config.GnutlsConfig), c, module.ModuleNameGnutls)
	return
}

func (hs *HttpServer) Gotls(c *gin.Context) {
	hs.decodeConf(new(config.GoTLSConfig), c, module.ModuleNameGotls)
	return
}

func (hs *HttpServer) Nss(c *gin.Context) {
	hs.decodeConf(new(config.NsprConfig), c, module.ModuleNameNspr)
	return
}

func (hs *HttpServer) decodeConf(ic config.IConfig, c *gin.Context, modName string) {
	if err := c.ShouldBindJSON(&ic); err != nil {
		c.JSON(http.StatusBadRequest, Resp{
			Code:       RespConfigDecodeFailed,
			ModuleType: modName,
			Msg:        RespConfigDecodeFailed.String(),
			Data:       nil,
		})
		return
	}
	// check config
	err := ic.Check()
	if err != nil {
		c.JSON(http.StatusBadRequest, Resp{
			Code:       RespConfigCheckFailed,
			ModuleType: modName,
			Msg:        RespConfigCheckFailed.String(),
			Data:       nil,
		})
		return
	}

	// send to channel
	select {
	case hs.confChan <- ic:
		c.JSON(http.StatusOK, Resp{
			Code:       RespOK,
			ModuleType: modName,
			Msg:        RespOK.String(),
			Data:       nil,
		})
	default:
		c.JSON(http.StatusServiceUnavailable, Resp{
			Code:       RespSendToChanFailed,
			ModuleType: modName,
			Msg:        RespSendToChanFailed.String(),
			Data:       nil,
		})
	}
	hs.logger.Info().RawJSON("config", ic.Bytes()).Msg("config send to channel.")
	return
}
