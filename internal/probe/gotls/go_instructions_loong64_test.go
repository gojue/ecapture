package gotls

import "testing"

func TestDecodeInstructionLoong64(t *testing.T) {
	// JIRL $r0, $r1, 0 is the LoongArch ABI return instruction. Instructions
	// are fixed-width and little-endian on linux/loong64.
	offsets, err := decodeInstruction([]byte{0x20, 0x00, 0x00, 0x4c})
	if err != nil {
		t.Fatalf("decodeInstruction(ret): %v", err)
	}
	if len(offsets) != 1 || offsets[0] != 0 {
		t.Fatalf("decodeInstruction(ret) = %v, want [0]", offsets)
	}

	if _, err := decodeInstruction([]byte{0x20, 0x00}); err == nil {
		t.Fatal("decodeInstruction accepted a truncated LoongArch instruction")
	}
}
