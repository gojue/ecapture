package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/gojue/ecapture/pkg/upgrade"
	"golang.org/x/sys/unix"
	"regexp"
	"strings"
)

const urlReleases = "https://api.github.com/repos/gojue"
const urlReleasesCN = "https://image.cnxct.com"
const apiReleases string = "/ecapture/releases/latest"

var (
	ErrOsArchNotFound       = errors.New("new tag found, but no os/arch match")
	ErrAheadOfLatestVersion = errors.New("local version is ahead of latest version")
)

func upgradeCheck(ctx context.Context) (string, string, error) {

	// uname -a
	var uname unix.Utsname
	err := unix.Uname(&uname)
	if err != nil {
		return "", "", fmt.Errorf("Error getting uname: %v", err)
	}
	var useragent = fmt.Sprintf("eCapture Cli (%s %s %s)",
		byteToString(uname.Sysname[:]), // 系统名称
		byteToString(uname.Release[:]), // 版本号
		byteToString(uname.Machine[:]), // 机器类型
	)
	var arch = "amd64"
	if byteToString(uname.Machine[:]) == "aarch64" {
		arch = "arm64"
	}
	rex := regexp.MustCompile(`([^:]*):v?(\d+\.\d+\.\d+)[^:]*:[^:]*`)
	verMatch := rex.FindStringSubmatch(GitVersion)
	if len(verMatch) <= 2 {
		return "", "", fmt.Errorf("error matching version: %s, verMatch:%v", GitVersion, verMatch)
	}
	var os = "linux"
	if strings.Contains(verMatch[1], "androidgki") {
		os = "android"
	}
	githubResp, err := upgrade.GetLatestVersion(useragent, fmt.Sprintf("%s%s?ver=%s", urlReleasesCN, apiReleases, GitVersion), ctx)
	if err != nil {
		return "", "", fmt.Errorf("error getting latest version: %v", err)
	}

	comp, err := upgrade.CheckVersion(verMatch[2], githubResp.TagName)
	if err != nil {
		return "", "", fmt.Errorf("error checking version: %v", err)
	}

	if comp >= 0 {
		return "", "", ErrAheadOfLatestVersion
	}

	// "name": "ecapture-v0.8.12-android-amd64.tar.gz",
	var targetAsset = fmt.Sprintf("ecapture-%s-%s-%s.tar.gz", githubResp.TagName, os, arch)
	for _, asset := range githubResp.Assets {
		if asset.Name == targetAsset {
			return githubResp.TagName, asset.BrowserDownloadURL, nil
		}
	}
	return "", "", ErrOsArchNotFound
}

func byteToString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
