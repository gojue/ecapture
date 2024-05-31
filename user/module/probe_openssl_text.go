package module

import (
	"errors"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"golang.org/x/sys/unix"
	"math"
	"os"
	"path"
	"strings"
)

func (m *MOpenSSLProbe) setupManagersText() error {
	var binaryPath, sslVersion string
	sslVersion = m.conf.(*config.OpensslConfig).SslVersion
	sslVersion = strings.ToLower(sslVersion)
	switch m.conf.(*config.OpensslConfig).ElfType {
	//case config.ElfTypeBin:
	//	binaryPath = m.conf.(*config.OpensslConfig).Curlpath
	case config.ElfTypeSo:
		binaryPath = m.conf.(*config.OpensslConfig).Openssl
		err := m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	default:
		//如果没找到
		binaryPath = path.Join(defaultSoPath, "libssl.so.1.1")
		err := m.getSslBpfFile(binaryPath, sslVersion)
		if err != nil {
			return err
		}
	}

	_, err := os.Stat(binaryPath)
	if err != nil {
		return err
	}

	m.logger.Info().Str("binrayPath", binaryPath).Uint8("ElfType", m.conf.(*config.OpensslConfig).ElfType).Strs("Functions", m.masterHookFuncs).Msg("Hook masterKey function")
	m.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{

			{
				Section:          "uprobe/SSL_write",
				EbpfFuncName:     "probe_entry_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/SSL_write",
				EbpfFuncName:     "probe_ret_SSL_write",
				AttachToFuncName: "SSL_write",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uprobe/SSL_read",
				EbpfFuncName:     "probe_entry_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/SSL_read",
				EbpfFuncName:     "probe_ret_SSL_read",
				AttachToFuncName: "SSL_read",
				BinaryPath:       binaryPath,
			},

			// --------------------------------------------------
			{
				Section:          "kprobe/sys_connect",
				EbpfFuncName:     "probe_connect",
				AttachToFuncName: "__sys_connect",
				UID:              "kprobe_sys_connect",
			},
			{
				Section:          "kprobe/sys_connect",
				EbpfFuncName:     "probe_connect",
				AttachToFuncName: "__sys_accept4",
				UID:              "kprobe_sys_accept4",
			},

			// --------------------------------------------------

			// openssl masterkey
			/*{
				Section:          "uprobe/SSL_write_key",
				EbpfFuncName:     "probe_ssl_master_key",
				AttachToFuncName: m.masterHookFuncs,
				BinaryPath:       binaryPath,
				UID:              "uprobe_ssl_master_key",
			},*/

			// ------------------- SSL_set_fd hook-------------------------------------
			{
				Section:          "uprobe/SSL_set_fd",
				EbpfFuncName:     "probe_SSL_set_fd",
				AttachToFuncName: "SSL_set_fd",
				BinaryPath:       binaryPath,
				UID:              "uprobe_ssl_set_fd",
			},
			{
				Section:          "uprobe/SSL_set_rfd",
				EbpfFuncName:     "probe_SSL_set_fd",
				AttachToFuncName: "SSL_set_rfd",
				BinaryPath:       binaryPath,
				UID:              "uprobe_ssl_set_rfd",
			},
			{
				Section:          "uprobe/SSL_set_wfd",
				EbpfFuncName:     "probe_SSL_set_fd",
				AttachToFuncName: "SSL_set_wfd",
				BinaryPath:       binaryPath,
				UID:              "uprobe_ssl_set_wfd",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "tls_events",
			},
			{
				Name: "connect_events",
			},
			//{
			//	Name: "mastersecret_events",
			//},
		},
	}

	m.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if m.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		m.bpfManagerOptions.ConstantEditors = m.constantEditor()
	} else {
		m.logger.Warn().Msg("Your kernel version is less than 5.2, GlobalVar is disabled, the following parameters will be ignored:[target_pid, target_uid, target_port]")
	}
	return nil
}

func (m *MOpenSSLProbe) initDecodeFunText() error {
	//SSLDumpEventsMap 与解码函数映射
	SSLDumpEventsMap, found, err := m.bpfManager.GetMap("tls_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tls_events")
	}
	m.eventMaps = append(m.eventMaps, SSLDumpEventsMap)
	sslEvent := &event.SSLDataEvent{}
	m.eventFuncMaps[SSLDumpEventsMap] = sslEvent

	ConnEventsMap, found, err := m.bpfManager.GetMap("connect_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:connect_events")
	}
	m.eventMaps = append(m.eventMaps, ConnEventsMap)
	connEvent := &event.ConnDataEvent{}
	m.eventFuncMaps[ConnEventsMap] = connEvent
	/*
		MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_events")
		if err != nil {
			return err
		}
		if !found {
			return errors.New("cant found map:mastersecret_events")
		}
		m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

		var masterkeyEvent event.IEventStruct

		if m.isBoringSSL {
			masterkeyEvent = &event.MasterSecretBSSLEvent{}
		} else {
			masterkeyEvent = &event.MasterSecretEvent{}
		}
		//masterkeyEvent.SetModule(m)
		m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	*/
	return nil
}
