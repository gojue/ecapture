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
func GetModules() map[string]IModule {
	return modules
}
