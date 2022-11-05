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

var modules = make(map[string]IModule)

func Register(p IModule) {
	if p == nil {
		panic("Register probe is nil")
	}
	name := p.Name()
	if _, dup := modules[name]; dup {
		panic(fmt.Sprintf("Register called twice for probe %s", name))
	}
	modules[name] = p
}

// GetModules 获取modules列表
func GetAllModules() map[string]IModule {
	return modules
}

// GetModulesByName 根据模块名获取modules列表
func GetModuleByName(modName string) IModule {
	m, f := modules[modName]
	if f {
		return m
	}
	return nil
}
