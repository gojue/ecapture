package user

import "fmt"

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
