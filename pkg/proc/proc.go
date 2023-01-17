package proc

import (
	"debug/buildinfo"
	"errors"
	"strconv"
	"strings"
)

const (
	goVersionPrefix = "Go cmd/compile "
)

// ErrVersionNotFound is returned when we can't find Go version info from a binary
var ErrVersionNotFound = errors.New("version info not found")

// GoVersion represents Go toolchain version that a binary is built with.
type GoVersion struct {
	major int
	minor int
}

// After returns true if it is greater than major.minor
func (v *GoVersion) After(major, minor int) bool {
	if v.major > minor {
		return true
	}
	if v.major == major && v.minor > minor {
		return true
	}
	return false
}

// ExtraceGoVersion extracts Go version info from a binary that is built with Go toolchain
func ExtraceGoVersion(path string) (*GoVersion, error) {
	bi, e := buildinfo.ReadFile(path)
	if e != nil {
		return nil, ErrVersionNotFound
	}
	gv, err := parseGoVersion(bi.GoVersion)
	if err != nil {
		return nil, err
	}
	return gv, nil
}

func parseGoVersion(r string) (*GoVersion, error) {
	ver := strings.TrimPrefix(r, goVersionPrefix)

	if strings.HasPrefix(ver, "go") {
		v := strings.SplitN(ver[2:], ".", 3)
		var major, minor int
		var err error

		major, err = strconv.Atoi(v[0])
		if err != nil {
			return nil, err
		}

		if len(v) >= 2 {
			minor, err = strconv.Atoi(v[1])
			if err != nil {
				return nil, err
			}
		}

		return &GoVersion{
			major: major,
			minor: minor,
		}, nil
	}
	return nil, ErrVersionNotFound
}
