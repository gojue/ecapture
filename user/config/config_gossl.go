// Copyright © 2022 Hengqi Chen
package config

import (
	"errors"
	"os"
)

var (
	ErrorGoBINNotSET = errors.New("GO binary not set")
)

// GoTLSConfig represents configuration for Go SSL probe
type GoTLSConfig struct {
	eConfig
	Path string
}

// NewGoTLSConfig creates a new config for Go SSL
func NewGoTLSConfig() *GoTLSConfig {
	return &GoTLSConfig{}
}

func (c *GoTLSConfig) Check() error {
	if c.Path == "" {
		return ErrorGoBINNotSET
	}
	_, err := os.Stat(c.Path)
	return err
}
