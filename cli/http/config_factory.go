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

	"github.com/gojue/ecapture/internal/domain"
	bashProbe "github.com/gojue/ecapture/internal/probe/bash"
	gotlsProbe "github.com/gojue/ecapture/internal/probe/gotls"
	opensslProbe "github.com/gojue/ecapture/internal/probe/openssl"
)

// createOpensslConfig creates and decodes OpenSSL probe configuration from HTTP request
func createOpensslConfig(c *gin.Context) (domain.Configuration, error) {
	conf := opensslProbe.NewConfig()
	if err := c.ShouldBindJSON(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// createGotlsConfig creates and decodes GoTLS probe configuration from HTTP request
func createGotlsConfig(c *gin.Context) (domain.Configuration, error) {
	conf := gotlsProbe.NewConfig()
	if err := c.ShouldBindJSON(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// createBashConfig creates and decodes Bash probe configuration from HTTP request
func createBashConfig(c *gin.Context) (domain.Configuration, error) {
	conf := bashProbe.NewConfig()
	if err := c.ShouldBindJSON(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

