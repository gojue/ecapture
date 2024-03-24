package config

import (
	"golang.org/x/arch/arm64/arm64asm"
)

const (
	// Arm64armInstSize via :  arm64/arm64asm/decode.go:Decode() size = 4
	Arm64armInstSize = 4
)

// decodeInstruction Decode into assembly instructions and identify the RET instruction to return the offset.
func (gc *GoTLSConfig) decodeInstruction(instHex []byte) ([]int, error) {
	var offsets []int
	for i := 0; i < len(instHex); {
		inst, _ := arm64asm.Decode(instHex[i:]) // Why ignore error: https://github.com/gojue/ecapture/pull/506
		if inst.Op == arm64asm.RET {
			offsets = append(offsets, i)
		}
		i += Arm64armInstSize
	}
	return offsets, nil
}
