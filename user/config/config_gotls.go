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
	Path   string `json:"path"`   // path to binary built with Go toolchain.
	Write  string `json:"write"`  // Write  the  raw  packets  to file rather than parsing and printing them out.
	Ifname string `json:"ifName"` // (TC Classifier) Interface name on which the probe will be attached.
	Port   uint16 `json:"port"`   // capture port
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
