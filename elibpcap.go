package elibpcap

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

func Inject(filter string, insns asm.Instructions, opts Options) (_ asm.Instructions, err error) {
	if filter == "" {
		return
	}

	injectIdx := -1
	for idx, inst := range insns {
		if inst.Symbol() == opts.AtBpf2Bpf {
			injectIdx = idx
			break
		}
	}
	if injectIdx == -1 {
		err = fmt.Errorf("Cannot find bpf2bpf: %s", opts.AtBpf2Bpf)
		return
	}

	filterInsns, err := CompileEbpf(filter, cbpfc.EBPFOpts{
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      asm.R0,
		ResultLabel: "result",
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "filter",
		StackOffset: 80,
	})
	if err != nil {
		return
	}

	filterInsns[0] = filterInsns[0].WithMetadata(insns[injectIdx].Metadata)
	insns[injectIdx] = insns[injectIdx].WithMetadata(asm.Metadata{})
	insns = append(insns[:injectIdx],
		append(filterInsns, insns[injectIdx:]...)...,
	)

	return insns, nil
}
