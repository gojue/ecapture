// Copyright © 2022 Hengqi Chen
package user

import (
	"errors"
	"os"
)

var (
	ErrorGoBINNotFound = errors.New("GO binary not found")
)

// GoSSLConfig represents configuration for Go SSL probe
type GoSSLConfig struct {
	eConfig
	Path string
}

// NewGoSSLConfig creates a new config for Go SSL
func NewGoSSLConfig() *GoSSLConfig {
	return &GoSSLConfig{}
}

func (c *GoSSLConfig) Check() error {
	if c.Path == "" {
		return ErrorGoBINNotFound
	}
	_, err := os.Stat(c.Path)
	return err
}
