// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gojue/ecapture/v2/internal/domain"
)

// BuildTime and BuildCommit are populated by the production linker recipe.
// A development build leaves unavailable build information empty.
var BuildTime, BuildCommit string

// collectorInfo is an operational snapshot, never a command to execute. It
// describes this collector process, not a captured process or its environment.
type collectorInfo struct {
	Host             string   `json:"host,omitempty"`
	Module           string   `json:"module,omitempty"`
	Mode             string   `json:"mode,omitempty"`
	TextSource       string   `json:"textSource,omitempty"`
	Argv             []string `json:"argv,omitempty"`
	ArgvTruncated    bool     `json:"argvTruncated,omitempty"`
	Version          string   `json:"version,omitempty"`
	BuildTime        string   `json:"buildTime,omitempty"`
	DecryptorVersion string   `json:"decryptorVersion,omitempty"`
	Commit           string   `json:"commit,omitempty"`
	ConfigListen     string   `json:"configListen,omitempty"`
	StreamListen     string   `json:"streamListen,omitempty"`
	Outputs          []string `json:"outputs,omitempty"`
	OutputsTruncated bool     `json:"outputsTruncated,omitempty"`
}

func newCollectorInfo(argv []string) collectorInfo {
	host, _ := os.Hostname()
	info := collectorInfo{
		Host: boundedInfoString(host, 256), Version: boundedInfoString(GitVersion, 512),
		Commit:       boundedInfoString(BuildCommit, 128),
		ConfigListen: boundedInfoString(globalConf.ConfigListen, 2048),
		StreamListen: boundedInfoString(globalConf.StreamListen, 2048),
	}
	if built, err := time.Parse(time.RFC3339, BuildTime); err == nil {
		info.BuildTime = built.UTC().Format(time.RFC3339)
	}
	info.Argv, info.ArgvTruncated = boundedInfoWords(argv, 256, 8192)
	outputs := globalConf.Outputs
	if len(outputs) == 0 {
		outputs = []string{"stdout"}
	}
	info.Outputs, info.OutputsTruncated = boundedInfoWords(outputs, 64, 8192)
	if build, ok := debug.ReadBuildInfo(); ok {
		info.DecryptorVersion = boundedInfoString(decryptorBuildVersion(build), 512)
		if info.Commit == "" {
			for _, setting := range build.Settings {
				if setting.Key == "vcs.revision" {
					info.Commit = boundedInfoString(setting.Value, 128)
				}
			}
		}
	}
	return info
}

func (info collectorInfo) forCapture(cfg domain.Configuration, module string) collectorInfo {
	info.Module = boundedInfoString(module, 64)
	info.Mode, info.TextSource = "text", ""
	if mode, ok := cfg.(domain.CaptureModeConfiguration); ok {
		info.Mode = boundedInfoString(mode.GetCaptureMode(), 64)
	}
	if source, ok := cfg.(domain.TextSourceConfiguration); ok && info.Mode == "text" {
		info.TextSource = boundedInfoString(source.GetTextSource(), 64)
	}
	return info
}

func decryptorBuildVersion(build *debug.BuildInfo) string {
	for _, dependency := range build.Deps {
		if dependency.Path != "github.com/gojue/ecapture_decryptor" {
			continue
		}
		if dependency.Replace != nil {
			// A local replacement has no verifiable release version. Do not
			// present the replaced module's original pin as the running code.
			if dependency.Replace.Version == "" {
				return "(local replacement)"
			}
			return dependency.Replace.Path + "@" + dependency.Replace.Version
		}
		return dependency.Version
	}
	return ""
}

func boundedInfoString(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func boundedInfoWords(values []string, maxWords, maxBytes int) ([]string, bool) {
	result := make([]string, 0, min(len(values), maxWords))
	truncated := false
	for _, value := range values {
		if len(result) == maxWords || maxBytes == 0 {
			return result, true
		}
		bounded := boundedInfoString(value, maxBytes)
		truncated = truncated || bounded != value
		result = append(result, bounded)
		if len(bounded) < len(strings.ToValidUTF8(value, "�")) {
			return result, true
		}
		maxBytes -= len(bounded)
	}
	return result, truncated
}
