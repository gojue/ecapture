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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

type HttpServer struct {
	//
	loadTime  int64  // 加载时间，防止短时间内多次加载
	loadStat  int8   // 加载状态，重启完成后，进行再次加载
	ProbeType string //当前加载探针类型
	probeConf any    //探针配置
	confChan  chan *ConfigUpdate
	handler   http.Handler
	addr      string
	logger    zerolog.Logger
}

func NewHttpServer(addr string, confChan chan *ConfigUpdate, zerologger zerolog.Logger) *HttpServer {
	hs := &HttpServer{
		confChan: confChan,
		addr:     addr,
		logger:   zerologger,
	}
	// Attach all endpoints - unavailable probes won't be registered due to build tags
	hs.attachEndpoints()
	return hs
}

func (hs *HttpServer) attachEndpoints() {
	mux := http.NewServeMux()
	// TLS/SSL related endpoints (available on both Linux and Android)
	mux.HandleFunc("POST /tls", hs.Tls)
	mux.HandleFunc("POST /openssl", hs.Tls)
	mux.HandleFunc("POST /boringssl", hs.Tls)
	mux.HandleFunc("POST /gotls", hs.Gotls)

	// Shell endpoints (bash available on both, others Linux-only but registered here)
	mux.HandleFunc("POST /bash", hs.Bash)

	// Database and other Linux-specific endpoints (will fail gracefully if probe not registered)
	mux.HandleFunc("POST /gnutls", hs.Gnutls)
	mux.HandleFunc("POST /mysqld", hs.Mysqld)
	mux.HandleFunc("POST /postgres", hs.Postgress)
	mux.HandleFunc("POST /postgress", hs.Postgress)
	mux.HandleFunc("POST /nss", hs.Nss)
	mux.HandleFunc("POST /nspr", hs.Nss)
	hs.handler = hs.logAndRecover(mux)
}

func (hs HttpServer) Run() error {
	return http.ListenAndServe(hs.addr, hs.handler)
}

func (hs *HttpServer) Tls(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "openssl")
}

func (hs *HttpServer) Gnutls(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "gnutls")
}

func (hs *HttpServer) Mysqld(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "mysql")
}

func (hs *HttpServer) Postgress(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "postgres")
}

func (hs *HttpServer) Gotls(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "gotls")
}

func (hs *HttpServer) Nss(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "nspr")
}

func (hs *HttpServer) Bash(w http.ResponseWriter, r *http.Request) {
	hs.decodeConf(w, r, "bash")
}

func (hs *HttpServer) decodeConf(w http.ResponseWriter, r *http.Request, probeType string) {
	// Create appropriate config based on probe type
	var update *ConfigUpdate
	var err error

	switch probeType {
	case "openssl":
		update, err = createOpensslConfig(r)
	case "gnutls":
		update, err = createGnutlsConfig(r)
	case "gotls":
		update, err = createGotlsConfig(r)
	case "nspr":
		update, err = createNsprConfig(r)
	case "bash":
		update, err = createBashConfig(r)
	case "mysql":
		update, err = createMysqlConfig(r)
	case "postgres":
		update, err = createPostgresConfig(r)
	default:
		writeJSON(w, http.StatusBadRequest, Resp{
			Code:       RespErrorNotFound,
			ModuleType: probeType,
			Msg:        "unknown probe type",
			Data:       nil,
		})
		return
	}

	if err != nil {
		writeJSON(w, http.StatusBadRequest, Resp{
			Code:       RespConfigDecodeFailed,
			ModuleType: probeType,
			Msg:        err.Error(),
			Data:       nil,
		})
		return
	}

	// Submit the candidate, then wait for the runtime to finish validation and
	// the real generation switch. A queued request is not yet a successful
	// reload.
	select {
	case hs.confChan <- update:
	default:
		writeJSON(w, http.StatusServiceUnavailable, Resp{
			Code:       RespSendToChanFailed,
			ModuleType: probeType,
			Msg:        RespSendToChanFailed.String(),
			Data:       nil,
		})
		return
	}

	select {
	case applyErr := <-update.Result():
		if applyErr != nil {
			writeJSON(w, http.StatusBadRequest, Resp{
				Code:       RespConfigCheckFailed,
				ModuleType: probeType,
				Msg:        applyErr.Error(),
				Data:       nil,
			})
			return
		}
		writeJSON(w, http.StatusOK, Resp{
			Code:       RespOK,
			ModuleType: probeType,
			Msg:        RespOK.String(),
			Data:       nil,
		})
	case <-r.Context().Done():
		return
	}
	hs.logger.Info().Interface("config", update.Config).Msg("config applied.")
}

func writeJSON(w http.ResponseWriter, status int, response Resp) {
	body, err := json.Marshal(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Prevent browsers from ever sniffing the JSON body as HTML. The JSON
	// encoding already escapes <, > and & (json.Marshal does this by default),
	// so this header is defense-in-depth against reflected-XSS.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (hs *HttpServer) logAndRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		response := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if recovered := recover(); recovered != nil {
				hs.logger.Error().Interface("panic", recovered).Str("path", r.URL.Path).Msg("HTTP handler panic")
				response.WriteHeader(http.StatusInternalServerError)
			}
			hs.logger.Info().Str("method", r.Method).Str("path", r.URL.Path).
				Int("status", response.status).Dur("duration", time.Since(started)).Msg("HTTP request")
		}()
		next.ServeHTTP(response, r)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}
