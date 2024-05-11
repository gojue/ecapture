// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package config

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"errors"
)

func GlobMany(targets []string, onErr func(string, error)) []string {
	rv := make([]string, 0, 20)
	addFile := func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rv = append(rv, path)
		return err
	}

	for _, p := range targets {
		// "p" is a wildcard pattern? expand it:
		if strings.Contains(p, "*") {
			matches, err := filepath.Glob(p)
			if err == nil {
				// walk each match:
				for _, p := range matches {
					e := filepath.Walk(p, addFile)
					if e != nil {
						continue
					}
				}
			}
			// path is not a wildcard, walk it:
		} else {
			e := filepath.Walk(p, addFile)
			if e != nil {
				return []string{}
			}
		}
	}
	return rv
}

// ParseDynLibConf reads/parses DL config files defined as a pattern
// and returns a list of directories found in there (or an error).
func ParseDynLibConf(pattern string) (dirs []string, err error) {
	files := GlobMany([]string{pattern}, nil)

	for _, configFile := range files {
		if strings.Contains(configFile, "lib32") {
			continue
		}
		fd, err := os.Open(configFile)
		if err != nil {
			return dirs, err
		}
		defer fd.Close()

		sc := bufio.NewScanner(fd)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			// ignore comments and empty lines
			if len(line) == 0 || line[0] == '#' || line[0] == ';' {
				continue
			}
			// found "include" directive?
			words := strings.Fields(line)
			if strings.ToLower(words[0]) == "include" {
				subdirs, err := ParseDynLibConf(words[1])
				if err != nil && !os.IsNotExist(err) {
					return dirs, err
				}
				dirs = append(dirs, subdirs...)
			} else {
				dirs = append(dirs, line)
			}
		}
	}
	if len(dirs) <= 0 {
		err = errors.New(fmt.Sprintf("read keylogger :%s error .", pattern))
	}
	return dirs, err
}

// getDynsFromElf get shared objects from ELF keylogger
func getDynsFromElf(file string) ([]string, error) {
	f, e := elf.Open(file)
	if e != nil {
		return nil, e
	}
	neededs, err := f.DynString(elf.DT_NEEDED)
	return neededs, err
}

// getDynPathByElf found soPath by soName from elfName
func getDynPathByElf(elfName, soName string) (string, error) {

	sos, e := getDynsFromElf(elfName)
	if e != nil {
		return "", e
	}

	// search dynamic library form ld.so.conf
	var searchPath = GetDynLibDirs()
	realSoName := recurseDynStrings(sos, searchPath, soName)

	// if not found soName from elfName
	if len(realSoName) == 0 {
		return "", errors.New(fmt.Sprintf("cant found so lib from %s", elfName))
	}
	return realSoName, nil
}

func recurseDynStrings(dynSym []string, searchPath []string, soName string) string {
	var realSoName string
	for _, el := range dynSym {
		// check keylogger path here for library if it doesnot exists panic
		var fd *os.File
		for _, entry := range searchPath {
			path := filepath.Join(entry, el)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				fd, err = os.OpenFile(path, os.O_RDONLY, 0644)
				if err != nil {
					continue
				} else {
					// found
					if strings.HasPrefix(filepath.Base(path), soName) {
						realSoName = path
						break
					}

					// not match ,will open it, and recurse it
				}
			}
		}

		if len(realSoName) > 0 {
			return realSoName
		}

		if fd == nil {
			log.Fatal(fmt.Sprintf("cant found lib so:%s in dirs:%v", el, searchPath))
		}

		bint, err := elf.NewFile(fd)
		if err != nil {
			log.Fatal(err)
		}

		bDynSym, err := bint.DynString(elf.DT_NEEDED)
		if err != nil {
			log.Fatal(err)
		}

		realSoName = recurseDynStrings(bDynSym, searchPath, soName)
		if len(realSoName) > 0 {
			return realSoName
		}
	}
	// not found
	return ""
}
