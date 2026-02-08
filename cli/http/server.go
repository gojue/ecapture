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
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/internal/domain"
)

type HttpServer struct {
	//
	loadTime  int64  // 加载时间，防止短时间内多次加载
	loadStat  int8   // 加载状态，重启完成后，进行再次加载
	ProbeType string //当前加载探针类型
	probeConf any    //探针配置
	confChan  chan domain.Configuration
	ge        *gin.Engine
	addr      string
	logger    zerolog.Logger
}

func NewHttpServer(addr string, confChan chan domain.Configuration, zerologger zerolog.Logger) *HttpServer {
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
	// Attach all endpoints - unavailable probes won't be registered due to build tags
	hs.attachEndpoints()
	return hs
}

func (hs *HttpServer) attachEndpoints() {
	// TLS/SSL related endpoints (available on both Linux and Android)
	hs.ge.POST("/tls", hs.Tls)
	hs.ge.POST("/openssl", hs.Tls)
	hs.ge.POST("/boringssl", hs.Tls)
	hs.ge.POST("/gotls", hs.Gotls)

	// Shell endpoints (bash available on both, others Linux-only but registered here)
	hs.ge.POST("/bash", hs.Bash)

	// Database and other Linux-specific endpoints (will fail gracefully if probe not registered)
	hs.ge.POST("/gnutls", hs.Gnutls)
	hs.ge.POST("/mysqld", hs.Mysqld)
	hs.ge.POST("/postgres", hs.Postgress)
	hs.ge.POST("/postgress", hs.Postgress)
	hs.ge.POST("/nss", hs.Nss)
	hs.ge.POST("/nspr", hs.Nss)
}

func (hs HttpServer) Run() error {
	return hs.ge.Run(hs.addr)
}

func (hs *HttpServer) Tls(c *gin.Context) {
	hs.decodeConf(c, "openssl")
}

func (hs *HttpServer) Gnutls(c *gin.Context) {
	hs.decodeConf(c, "gnutls")
}

func (hs *HttpServer) Mysqld(c *gin.Context) {
	hs.decodeConf(c, "mysql")
}

func (hs *HttpServer) Postgress(c *gin.Context) {
	hs.decodeConf(c, "postgres")
}

func (hs *HttpServer) Gotls(c *gin.Context) {
	hs.decodeConf(c, "gotls")
}

func (hs *HttpServer) Nss(c *gin.Context) {
	hs.decodeConf(c, "nspr")
}

func (hs *HttpServer) Bash(c *gin.Context) {
	hs.decodeConf(c, "bash")
}

func (hs *HttpServer) decodeConf(c *gin.Context, probeType string) {
	// Create appropriate config based on probe type
	var conf domain.Configuration
	var err error

	switch probeType {
	case "openssl":
		conf, err = createOpensslConfig(c)
	case "gnutls":
		conf, err = createGnutlsConfig(c)
	case "gotls":
		conf, err = createGotlsConfig(c)
	case "nspr":
		conf, err = createNsprConfig(c)
	case "bash":
		conf, err = createBashConfig(c)
	case "mysql":
		conf, err = createMysqlConfig(c)
	case "postgres":
		conf, err = createPostgresConfig(c)
	default:
		c.JSON(http.StatusBadRequest, Resp{
			Code:       RespErrorNotFound,
			ModuleType: probeType,
			Msg:        "unknown probe type",
			Data:       nil,
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, Resp{
			Code:       RespConfigDecodeFailed,
			ModuleType: probeType,
			Msg:        err.Error(),
			Data:       nil,
		})
		return
	}

	// check config
	err = conf.Validate()
	if err != nil {
		c.JSON(http.StatusBadRequest, Resp{
			Code:       RespConfigCheckFailed,
			ModuleType: probeType,
			Msg:        err.Error(),
			Data:       nil,
		})
		return
	}

	// send to channel
	select {
	case hs.confChan <- conf:
		c.JSON(http.StatusOK, Resp{
			Code:       RespOK,
			ModuleType: probeType,
			Msg:        RespOK.String(),
			Data:       nil,
		})
	default:
		c.JSON(http.StatusServiceUnavailable, Resp{
			Code:       RespSendToChanFailed,
			ModuleType: probeType,
			Msg:        RespSendToChanFailed.String(),
			Data:       nil,
		})
	}
	hs.logger.Info().Interface("config", conf).Msg("config send to channel.")
}
