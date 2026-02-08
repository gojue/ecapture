//go:build ecap_android
// +build ecap_android

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
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/gojue/ecapture/internal/domain"
)

// createGnutlsConfig - GnuTLS is now supported on Android (via Termux or custom builds)
func createGnutlsConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, fmt.Errorf("GnuTLS probe not supported on Android")
}

// createNsprConfig - NSPR not supported on Android
func createNsprConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, fmt.Errorf("nspr probe not supported on Android")
}

// createMysqlConfig - MySQL not supported on Android
func createMysqlConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, fmt.Errorf("mysql probe not supported on Android")
}

// createPostgresConfig - Postgres not supported on Android
func createPostgresConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, fmt.Errorf("postgres probe not supported on Android")
}
