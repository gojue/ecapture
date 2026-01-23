package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/jschwinger233/elibpcap"
)

func injectPcapFilter(progSpec *ebpf.ProgramSpec, pcapFilter string) (*ebpf.ProgramSpec, error) {
	if pcapFilter == "" {
		return progSpec, nil
	}

	var err error
	progSpec.Instructions, err = elibpcap.Inject(pcapFilter, progSpec.Instructions, elibpcap.Options{
		AtBpf2Bpf: "filter_pcap_ebpf_l2",
		//DirectRead: true,
		L2Skb: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to inject pcap filter: %w", err)
	}

	return progSpec, nil
}

// PrepareInsnPatchers prepares instruction patcher functions for the given eBPF functions and pcap filter.
func PrepareInsnPatchers(m *manager.Manager, ebpfFuncs []string, pcapFilter string) []manager.InstructionPatcherFunc {
	preparePatcher := func(ebpfFunc string) manager.InstructionPatcherFunc {
		return func(m *manager.Manager) error {
			progSpecs, ok, err := m.GetProgramSpec(manager.ProbeIdentificationPair{EbpfFuncName: ebpfFunc})
			if err != nil || !ok || len(progSpecs) == 0 {
				return fmt.Errorf("failed to get program spec for %s: %w", ebpfFunc, err)
			}

			for _, progSpec := range progSpecs {
				_, err = injectPcapFilter(progSpec, pcapFilter)
				if err != nil {
					return fmt.Errorf("failed to inject pcap filter for %s: %w", ebpfFunc, err)
				}
			}

			return nil
		}
	}

	insnPatchers := make([]manager.InstructionPatcherFunc, 0, len(ebpfFuncs))
	for _, ebpfFunc := range ebpfFuncs {
		fn := ebpfFunc
		insnPatchers = append(insnPatchers, preparePatcher(fn))
	}

	return insnPatchers
}
