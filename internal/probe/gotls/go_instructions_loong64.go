package gotls

import "golang.org/x/arch/loong64/loong64asm"

const loong64InstructionSize = 4

// decodeInstruction returns the offsets of LoongArch JIRL $r0, $r1, 0
// instructions, which are the ABI return instruction rendered as "ret".
func decodeInstruction(instHex []byte) ([]int, error) {
	var offsets []int
	for i := 0; i < len(instHex); i += loong64InstructionSize {
		inst, err := loong64asm.Decode(instHex[i:])
		if err != nil {
			return nil, err
		}
		if inst.Op == loong64asm.JIRL && inst.String() == "ret" {
			offsets = append(offsets, i)
		}
	}
	return offsets, nil
}
