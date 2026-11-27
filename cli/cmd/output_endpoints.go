// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/factory"
	outputpipeline "github.com/gojue/ecapture/v2/internal/output"
	"github.com/gojue/ecapture/v2/internal/output/writers"
)

type outputEndpoint struct{ address, kind string }

func parseOutputEndpoints(values []string) ([]outputEndpoint, error) {
	if len(values) == 0 {
		values = []string{"stdout"}
	}
	var result []outputEndpoint
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("--output cannot be empty")
		}
		endpoint := outputEndpoint{address: value}
		switch value {
		case "stdout", "stderr":
			endpoint.kind = value
		case "console", "-":
			return nil, fmt.Errorf("--output %q is unsupported; use stdout or stderr", value)
		default:
			u, err := url.Parse(value)
			if err != nil {
				return nil, err
			}
			if u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" {
				return nil, fmt.Errorf("invalid --output URL %q", value)
			}
			switch u.Scheme {
			case "", "file":
				path := value
				if u.Scheme == "file" {
					if u.Host != "" && u.Host != "localhost" {
						return nil, fmt.Errorf("file output must be local")
					}
					path = u.Path
				}
				if path == "" {
					return nil, fmt.Errorf("file output requires a path")
				}
				endpoint.address, err = filepath.Abs(path)
				if err != nil {
					return nil, err
				}
				endpoint.kind = "file"
				if info, err := os.Stat(endpoint.address); err == nil && !info.Mode().IsRegular() && info.Mode()&os.ModeNamedPipe == 0 {
					return nil, fmt.Errorf("output file must be a regular file or FIFO: %s", path)
				} else if err != nil && !os.IsNotExist(err) {
					return nil, err
				}
			case "tcp":
				if err := validateEndpointHost(u.Host); err != nil {
					return nil, err
				}
				if u.Path != "" {
					return nil, fmt.Errorf("TCP output cannot contain a path")
				}
				endpoint.kind = "network"
			default:
				return nil, fmt.Errorf("unsupported --output scheme %q; use stdout, stderr, file, or tcp", u.Scheme)
			}
		}
		for _, previous := range result {
			if previous.address == endpoint.address || previous.kind == "file" && endpoint.kind == "file" && sameOutputFile(previous.address, endpoint.address) {
				return nil, fmt.Errorf("duplicate --output destination %q", value)
			}
		}
		result = append(result, endpoint)
	}
	return result, nil
}
func validateEndpointHost(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return fmt.Errorf("address requires host:port: %q", address)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}
func parseStreamAddress(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
		return nil, fmt.Errorf("--stream-listen requires ws://host:port/path")
	}
	if err := validateEndpointHost(u.Host); err != nil {
		return nil, err
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}
func sameOutputFile(a, b string) bool {
	clean := func(p string) string {
		if u, err := url.Parse(p); err == nil && u.Scheme == "file" {
			p = u.Path
		}
		p, _ = filepath.Abs(p)
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		if parent, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			return filepath.Join(parent, filepath.Base(p))
		}
		return p
	}
	a, b = clean(a), clean(b)
	if a == b {
		return true
	}
	ai, ae := os.Stat(a)
	bi, be := os.Stat(b)
	return ae == nil && be == nil && os.SameFile(ai, bi)
}
func validateOutputArtifacts(cfg domain.Configuration, endpoints []outputEndpoint) error {
	provider, ok := cfg.(interface {
		GetPcapFile() string
		GetKeylogFile() string
	})
	if !ok {
		return nil
	}
	artifacts := []string{provider.GetPcapFile(), provider.GetKeylogFile()}
	for i, a := range artifacts {
		if a == "" {
			continue
		}
		if err := writers.ValidateArtifactFile(a); err != nil {
			return err
		}
		for _, e := range endpoints {
			if e.kind == "file" && sameOutputFile(e.address, a) {
				return fmt.Errorf("--output file and native capture artifact must use different files")
			}
		}
		for _, b := range artifacts[:i] {
			if b != "" && sameOutputFile(a, b) {
				return fmt.Errorf("pcapfile and keylogfile must use different files")
			}
		}
	}
	return nil
}
func moduleName(kind factory.ProbeType) string {
	switch kind {
	case factory.ProbeTypeOpenSSL:
		return "tls"
	case factory.ProbeTypeGoTLS:
		return "gotls"
	case factory.ProbeTypeGnuTLS:
		return "gnutls"
	default:
		return strings.ToLower(string(kind))
	}
}

type combinedPublisher interface {
	domain.OperationalLogSink
	domain.CapturedEventSink
}
type outputTarget struct {
	endpoint  outputEndpoint
	publisher combinedPublisher
}

// outputSet owns the endpoint array. Files/terminals survive reload, while a
// native TCP stream is closed and reopened at the next generation boundary.
type outputSet struct {
	mu        sync.RWMutex
	targets   []outputTarget
	module    string
	failures  chan error
	closed    bool
	failureMu sync.Mutex
	failure   error
	closeErr  error
}

func newOutputSet(endpoints []outputEndpoint, module string) (*outputSet, error) {
	s := &outputSet{module: module, failures: make(chan error, 1)}
	for _, e := range endpoints {
		p, err := openOutput(e)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		s.targets = append(s.targets, outputTarget{endpoint: e, publisher: p})
	}
	return s, nil
}
func openOutput(e outputEndpoint) (combinedPublisher, error) {
	if e.kind == "stdout" {
		return outputpipeline.NewConsolePublisher("stdout", os.Stdout), nil
	}
	if e.kind == "stderr" {
		return outputpipeline.NewConsolePublisher("stderr", os.Stderr), nil
	}
	address := e.address
	if e.kind == "file" {
		// The endpoint holds a decoded path, while the factory accepts URLs.
		// Re-encode literal percent signs before crossing that boundary.
		address = (&url.URL{Scheme: "file", Path: e.address}).String()
	}
	sink, err := writers.NewWriterFactory().CreateJSONSink(address)
	if err != nil {
		return nil, err
	}
	publisher, err := outputpipeline.NewJSONPublisher(sink)
	if err != nil {
		_ = sink.Close()
		return nil, err
	}
	return publisher, nil
}
func (s *outputSet) Name() string { return "output" }
func (s *outputSet) report(err error) error {
	if err != nil {
		s.failureMu.Lock()
		if s.failure == nil {
			s.failure = err
		}
		s.failureMu.Unlock()
		select {
		case s.failures <- err:
		default:
		}
	}
	return err
}
func (s *outputSet) PublishLog(ctx context.Context, r domain.OperationalLogRecord) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("output set is closed")
	}
	r.Module = s.module
	var errs []error
	for _, t := range s.targets {
		if t.publisher != nil {
			if err := t.publisher.PublishLog(ctx, r); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return s.report(errors.Join(errs...))
}
func (s *outputSet) PublishEvent(ctx context.Context, e domain.CapturedEventEnvelope) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("output set is closed")
	}
	e.Module = s.module
	var errs []error
	for _, t := range s.targets {
		if t.publisher == nil || t.endpoint.kind == "file" && e.Format != domain.CaptureFormatText {
			continue
		}
		if err := t.publisher.PublishEvent(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return s.report(errors.Join(errs...))
}
func (s *outputSet) BeginCapture() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("output set is closed")
	}
	var opened []int
	for i := range s.targets {
		t := &s.targets[i]
		if t.publisher == nil {
			p, err := openOutput(t.endpoint)
			if err != nil {
				for _, index := range opened {
					_ = s.targets[index].publisher.Close()
					s.targets[index].publisher = nil
				}
				return err
			}
			t.publisher = p
			opened = append(opened, i)
		}
	}
	return nil
}
func (s *outputSet) EndCapture() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for i := range s.targets {
		t := &s.targets[i]
		if t.endpoint.kind == "network" && t.publisher != nil {
			errs = append(errs, t.publisher.Close())
			t.publisher = nil
		}
	}
	return s.report(errors.Join(errs...))
}
func (s *outputSet) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	var errs []error
	for i := range s.targets {
		t := &s.targets[i]
		if t.publisher != nil {
			errs = append(errs, t.publisher.Close())
			t.publisher = nil
		}
	}
	s.failureMu.Lock()
	s.closeErr = errors.Join(s.failure, errors.Join(errs...))
	s.failureMu.Unlock()
	return s.closeErr
}
