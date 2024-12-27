// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package upgrade

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"regexp"
	"strings"
	"testing"
)

const urlReleases = "https://api.github.com/repos/gojue"
const urlReleasesCN = "https://image.cnxct.com"
const apiReleases string = "/ecapture/releases/latest"

func TestCheckLatest(t *testing.T) {
	var uname unix.Utsname

	// 调用 uname 系统调用
	err := unix.Uname(&uname)
	if err != nil {
		t.Logf("Upgrader: Error getting uname: %v", err)
		return
	}

	var useragent = fmt.Sprintf("eCapture Cli %s %s %s",
		byteToString(uname.Sysname[:]), // 系统名称
		byteToString(uname.Release[:]), // 版本号
		byteToString(uname.Machine[:]), // 机器类型
	)
	t.Logf("User-Agent:%d, %s", len(useragent), useragent)
	//var ver = "linux_arm64:v0.8.8:5.15.0-125-generic"
	var ver = "androidgki:v0.8.8:5.15.0-125-generic"
	ver = "linux_arm64:v0.8.10-20241116-fcddaeb:5.15.0-125-generic"
	ver = "linux_arm64:v0.9.1:6.5.0-1025-azure"
	var arch = "amd64"
	if byteToString(uname.Machine[:]) == "aarch64" {
		arch = "arm64"
	}

	rex := regexp.MustCompile(`([^:]*):v?(\d+\.\d+\.\d+)[^:]*:[^:]*`)

	verMatch := rex.FindStringSubmatch(ver)
	if len(verMatch) <= 2 {
		t.Fatalf("Error matching version: %s", ver)
	}
	t.Logf("match Version: %v", verMatch)
	var os = "linux"
	if strings.Contains(verMatch[1], "androidgki") {
		os = "android"
	}

	githubResp, err := GetLatestVersion(useragent, fmt.Sprintf("%s%s?ver=%s", urlReleasesCN, apiReleases, ver), context.Background())
	if err != nil {
		t.Fatalf("Error getting latest version: %v", err)
	}

	t.Logf("Latest version: %v", githubResp.TagName)
	comp, err := CheckVersion(verMatch[2], githubResp.TagName)
	if err != nil {
		t.Fatalf("Error checking version: %v", err)
	}
	t.Logf("Version comparison: %v", comp)

	if comp >= 0 {
		t.Logf("Local version is ahead of latest version")
		return
	}

	t.Logf("Local version is behind latest version")

	//       "name": "ecapture-v0.8.12-android-amd64.tar.gz",
	var targetAsset = fmt.Sprintf("ecapture-%s-%s-%s.tar.gz", githubResp.TagName, os, arch)
	t.Logf("Target asset: %s", targetAsset)
	for _, asset := range githubResp.Assets {
		if asset.Name == targetAsset {
			t.Logf("Found target asset, downloadUrl:%s", asset.BrowserDownloadURL)
			break
		}
		//t.Logf("Asset: %s", asset.Name)
	}
}

func byteToString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
