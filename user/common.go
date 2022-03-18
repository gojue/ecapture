package user

import (
	"bufio"
	"debug/elf"
	"fmt"
	"github.com/pkg/errors"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	AF_FILE  = uint16(1)
	AF_INET  = uint16(2)
	AF_INET6 = uint16(10)
)

func inet_ntop(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func GetDynLibDirs() []string {
	dirs, err := ParseDynLibConf("/etc/ld.so.conf")
	if err != nil {
		log.Println(err.Error())
		return []string{"/usr/lib64", "/lib64"}
	}
	return append(dirs, "/lib64", "/usr/lib64")
}

func GlobMany(targets []string, onErr func(string, error)) []string {
	rv := make([]string, 0, 20)
	addFile := func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			log.Println(err.Error())
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
					filepath.Walk(p, addFile)
				}
			}
			// path is not a wildcard, walk it:
		} else {
			filepath.Walk(p, addFile)
		}
	}
	return rv
}

// ParseDynLibConf reads/parses DL config files defined as a pattern
// and returns a list of directories found in there (or an error).
func ParseDynLibConf(pattern string) (dirs []string, err error) {
	files := GlobMany([]string{pattern}, nil)

	for _, configFile := range files {
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
	return dirs, err
}

// getDynsFromElf get shared objects from ELF file
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
	var realSoName string
	for _, so := range sos {
		if strings.HasPrefix(so, soName) {
			realSoName = so
			break
		}
	}

	// if not found soName from elfName
	// return elfName self
	if len(realSoName) == 0 {
		return "", errors.New(fmt.Sprintf("cant found so lib from %s", elfName))
	}

	// search dynamic library form ld.so.conf
	var searchPath = GetDynLibDirs()
	for _, entry := range searchPath {
		path := filepath.Join(entry, realSoName)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return path, nil
		} else {
			// Nothing
		}
	}

	// try catch ,not found SO from ld.so.conf
	return "", errors.New(fmt.Sprintf("Not found lib:%s , from %v:searchPath"))
}
