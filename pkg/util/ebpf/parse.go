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

package ebpf

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

func parse(s *bufio.Scanner, p map[string]string) error {
	r, _ := regexp.Compile("^(?:# *)?(CONFIG_\\w*)(?:=| )(y|n|m|is not set|\\d+|0x.+|\".*\")$")

	for s.Scan() {

		t := s.Text()

		// Skip line if empty.
		if t == "" {
			continue
		}

		// 0 is the match of the entire expression,
		// 1 is the key, 2 is the value.
		m := r.FindStringSubmatch(t)
		if m == nil {
			continue
		}

		if len(m) != 3 {
			return fmt.Errorf("match is not 3 chars long: %v", m)
		}
		// Remove all leading and trailing double quotes from the value.
		if len(m[2]) > 1 {
			m[2] = strings.Trim(m[2], "\"")
		}

		// Insert entry into map.
		p[m[1]] = m[2]
	}

	if err := s.Err(); err != nil {
		return err
	}

	return nil
}
