package elibpcap

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

/*
If PacketAccessMode != Direct, We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory.
*/
func adjustEbpf(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	switch opts.PacketAccessMode {
	case BpfProbeReadKernel:
		insts, err = adjustEbpfWithBpfProbeReadKernel(insts, opts)
		if err != nil {
			return nil, err
		}
		break
	case BpfSkbLoadBytes:
		insts, err = adjustEbpfWithBpfSkbLoadBytes(insts, opts)
		if err != nil {
			return nil, err
		}
		break
	case Direct:
		break
	default:
		return nil, fmt.Errorf("unsupported packet access mode: %v", opts.PacketAccessMode)
	}

	return append(insts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(opts.resultLabel()), // r1 = 0 (_skb)
		asm.Mov.Imm(asm.R2, 0),                                // r2 = 0 (__skb)
		asm.Mov.Imm(asm.R3, 0),                                // r3 = 0 (___skb)
		asm.Mov.Reg(asm.R4, opts.result()),                    // r4 = $result (data)
		asm.Mov.Imm(asm.R5, 0),                                // r5 = 0 (data_end)
	), nil
}
