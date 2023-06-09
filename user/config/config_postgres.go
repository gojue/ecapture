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

package config

import (
	"os"
	"strings"

	"errors"
)

type PostgresConfig struct {
	eConfig
	PostgresPath string `json:"postgresPath"`
	FuncName     string `json:"funcName"`
}

func NewPostgresConfig() *PostgresConfig {
	config := &PostgresConfig{}
	return config
}

func (pc *PostgresConfig) Check() error {

	if pc.PostgresPath == "" || len(strings.TrimSpace(pc.PostgresPath)) <= 0 {
		return errors.New("Postgres path cant be null.")
	}

	_, e := os.Stat(pc.PostgresPath)
	if e != nil {
		return e
	}

	pc.FuncName = "exec_simple_query"
	return nil
}
