package ebpf

import (
	"testing"
)

// TestIsContainerCgroup is a test for isContainerCgroup
func TestBpfConfig(t *testing.T) {

	// 检测是否是容器
	isContainer, err := IsContainer()
	if err != nil {
		t.Fatal("Check container error:", err)
	}

	if isContainer {
		t.Logf("Your environment is a container. We will not detect the BTF config.")
		return
	}

	t.Log("TestBpfConfig with fake config")
	configPaths = []string{
		"/xxxxx/proc/config.gz", // android
	}
	m, e := GetSystemConfig()
	if e != nil {
		// 正常情况 是没有找到配置文件
		t.Logf("GetSystemConfig error:%s", e.Error())
	}

	t.Log("TestBpfConfig with true config")
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

func TestIsContainerCgroup(t *testing.T) {
	isContainer, err := isCOntainerCgroup()
	if err != nil {
		t.Fatalf("TestIsContainerCgroup :: IsContainer error:%s", err.Error())
	}
	if isContainer {
		t.Logf("TestIsContainerCgroup :: IsContainer true")
	} else {
		t.Logf("TestIsContainerCgroup :: IsContainer false")
	}
}

func TestIsContainerSched(t *testing.T) {
	isContainer, err := isCOntainerSched()
	if err != nil {
		t.Fatalf("TestIsContainerSched :: IsContainer error:%s", err.Error())
	}
	if isContainer {
		t.Logf("TestIsContainerSched :: IsContainer true")
	} else {
		t.Logf("TestIsContainerSched :: IsContainer false")
	}
}
