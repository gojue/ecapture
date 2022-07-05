package ebpf

import (
	"testing"
)

func TestBpfConfig(t *testing.T) {
	configPaths = []string{
		"/xxxxx/proc/config.gz", // android
	}
	m, e := GetSystemConfig()
	if e != nil {
		// 正常情况 是没有找到配置文件
		t.Logf("GetSystemConfig error:%s", e.Error())
	}

	configPaths = []string{
		"/proc/config.gz", // android
		"/boot/config",    // linux
		"/boot/config-%s", // linux
	}
	m, e = GetSystemConfig()
	if e != nil {
		t.Fatalf("GetSystemConfig error:%s", e.Error())
	}
	for _, item := range configCheckItems {
		bc, found := m[item]
		if !found {
			// 没有这个配置项
			t.Logf("Config not found,  item:%s.", item)
		}

		//如果有，在判断配置项的值
		if bc != "y" {
			// 没有开启
			t.Logf("Config disabled, item :%s.", item)
		}
	}
	t.Logf("GetSystemConfig success")
}
