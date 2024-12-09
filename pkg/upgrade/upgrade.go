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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/*

https://api.github.com/repos/gojue/ecapture/releases/latest
https://api.github.com/repos/gojue/ecapture/releases/tags/v0.1.0
https://github.com/gojue/ecapture/releases/download/v0.8.12/checksum-v0.8.12.txt

image.cnxct.com/ecapture/releases/latest
image.cnxct.com/ecapture/releases/tags/v0.1.0
image.cnxct.com/ecapture/download/v0.8.12/checksum-v0.8.12.txt
*/

// we use the GitHub REST V3 API as no login is required
// https://docs.github.com/zh/rest/using-the-rest-api

func GetLatestVersion(ua, url string, ctx context.Context) (GithubReleaseResp, error) {
	var release GithubReleaseResp
	err := makeGithubRequest(ctx, ua, url, &release)
	if err != nil {
		return release, err
	}

	return release, nil

}

func CheckVersion(localVer, remoteVer string) (int, error) {

	localVer = strings.ReplaceAll(localVer, "v", "")
	remoteVer = strings.ReplaceAll(remoteVer, "v", "")

	v1, err := ParseVersion(localVer)
	if err != nil {
		return 0, err
	}

	v2, err := ParseVersion(remoteVer)
	if err != nil {
		return 0, err
	}

	comparison := CompareVersions(v1, v2)
	return comparison, nil
}

func makeGithubRequest(ctx context.Context, ua, url string, output interface{}) error {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}

	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	req.Header.Add("Accept", "application/json") // gh api recommendation , send header with api version
	req.Header.Set("User-Agent", ua)             // eCapture Cli Linux 5.15.0-125-generic aarch64
	response, err := client.Do(req)
	if err != nil {
		//lint:ignore ST1005 Github is a proper capitalized noun
		return fmt.Errorf("API request failed: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		//lint:ignore ST1005 Github is a proper capitalized noun
		return fmt.Errorf("API request failed, statusCOde: %s", response.Status)
	}

	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		//lint:ignore ST1005 Github is a proper capitalized noun
		return fmt.Errorf("API read response failed: %w", err)
	}

	err = json.Unmarshal(data, output)
	if err != nil {
		return fmt.Errorf("unmarshalling Github API response failed: %w", err)
	}

	return nil
}

// Version 结构体表示一个版本号
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion 解析版本号字符串
func ParseVersion(versionStr string) (Version, error) {
	parts := strings.Split(versionStr, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid version format")
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, err
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return Version{}, err
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return Version{}, err
	}

	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// CompareVersions 比较两个版本号
func CompareVersions(v1, v2 Version) int {
	if v1.Major != v2.Major {
		return v1.Major - v2.Major
	}
	if v1.Minor != v2.Minor {
		return v1.Minor - v2.Minor
	}
	return v1.Patch - v2.Patch
}
