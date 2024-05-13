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

package module

import (
	"fmt"
)

var newModule = make(map[string]func() IModule)

// RegisteFunc register module function
func RegisteFunc(f func() IModule) {
	p := f()
	if p == nil {
		panic("function register probe is nil")
	}
	name := p.Name()
	if _, dup := newModule[name]; dup {
		panic(fmt.Sprintf("function register called twice for probe %s", name))
	}
	newModule[name] = f
}

// GetModuleFunc get module function by name
func GetModuleFunc(name string) func() IModule {
	f, ok := newModule[name]
	if !ok {
		return nil
	}
	return f
}
