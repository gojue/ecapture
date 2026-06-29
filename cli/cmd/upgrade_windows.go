//go:build windows
// +build windows

package cmd

import "context"

func upgradeCheck(_ context.Context) (string, string, error) {
	return "", "", nil
}
