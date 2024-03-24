package config

import (
	"golang.org/x/arch/x86/x86asm"
)

// decodeInstruction Decode into assembly instructions and identify the RET instruction to return the offset.
func (gc *GoTLSConfig) decodeInstruction(instHex []byte) ([]int, error) {
	var offsets []int
	for i := 0; i < len(instHex); {
		inst, err := x86asm.Decode(instHex[i:], 64)
		if err != nil {
			return nil, err
		}
		if inst.Op == x86asm.RET {
			offsets = append(offsets, i)
		}
		i += inst.Len
	}
	return offsets, nil
}
