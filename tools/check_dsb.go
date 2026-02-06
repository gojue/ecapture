package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// PCAPNG Block Types
const (
	BlockTypeSectionHeader        = 0x0A0D0D0A
	BlockTypeInterfaceDescription = 0x00000001
	BlockTypePacket               = 0x00000002
	BlockTypeSimplePacket         = 0x00000003
	BlockTypeNameResolution       = 0x00000004
	BlockTypeInterfaceStatistics  = 0x00000005
	BlockTypeEnhancedPacket       = 0x00000006
	BlockTypeDecryptionSecrets    = 0x0000000A // DSB block
	BlockTypeCustomCanCopy        = 0x00000BAD
	BlockTypeCustomNoCopy         = 0x40000BAD
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <pcapng_file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer func(file *os.File) {
		_ = file.Close()

	}(file)

	fmt.Printf("Analyzing PCAPNG file: %s\n", filename)
	fmt.Println("===========================================")

	blockNum := 0
	dsbCount := 0
	totalKeylogBytes := 0

	for {
		var blockType uint32
		var blockLength uint32

		// Read block type
		err := binary.Read(file, binary.LittleEndian, &blockType)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading block type: %v\n", err)
			break
		}

		// Read total block length
		err = binary.Read(file, binary.LittleEndian, &blockLength)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading block length: %v\n", err)
			break
		}

		blockNum++
		//blockName := getBlockName(blockType)

		//fmt.Printf("Block #%d: Type=0x%08X (%s), Length=%d bytes\n",
		//	blockNum, blockType, blockName, blockLength)

		if blockType == BlockTypeDecryptionSecrets {
			dsbCount++
			fmt.Printf("  ✓ Found DSB (Decryption Secrets Block) #%d\n", dsbCount)

			// Try to read DSB content
			if blockLength > 12 { // Min size: 4 (type) + 4 (length) + 4 (secrets type) + 4 (trailing length)
				// Read secrets type
				var secretsType uint32
				err = binary.Read(file, binary.LittleEndian, &secretsType)
				if err == nil {
					fmt.Printf("  Secrets Type: 0x%08X", secretsType)
					if secretsType == 0x544c534b { // "TLSK" in little-endian
						fmt.Printf(" (TLS Key Log)")
					}
					fmt.Println()

					// Read secrets length
					var secretsLength uint32
					err = binary.Read(file, binary.LittleEndian, &secretsLength)
					if err == nil {
						fmt.Printf("  Secrets Length: %d bytes\n", secretsLength)
						totalKeylogBytes += int(secretsLength)

						// Read first part of the keylog data
						if secretsLength > 0 && secretsLength < 1024 {
							keylogData := make([]byte, secretsLength)
							n, err := io.ReadFull(file, keylogData)
							if err == nil && n > 0 {
								fmt.Printf("  Keylog Data (first 200 chars):\n")
								if n > 200 {
									fmt.Printf("    %s...\n", string(keylogData[:200]))
								} else {
									fmt.Printf("    %s\n", string(keylogData))
								}
							}
							// Skip remaining block data
							remaining := int(blockLength) - 12 - 4 - 4 - int(secretsLength)
							if remaining > 0 {
								_, _ = file.Seek(int64(remaining), io.SeekCurrent)
							}
							continue
						} else {
							// Skip secrets data
							_, _ = file.Seek(int64(secretsLength), io.SeekCurrent)
						}
					}
				}
			}
		}

		// Skip to next block (blockLength includes the header and trailer)
		remaining := int64(blockLength) - 8 // Already read 8 bytes (type + length)
		if remaining > 0 {
			_, err = file.Seek(remaining, io.SeekCurrent)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error seeking: %v\n", err)
				break
			}
		}
	}

	fmt.Println("===========================================")
	fmt.Printf("Total blocks: %d\n", blockNum)
	fmt.Printf("DSB blocks found: %d\n", dsbCount)
	fmt.Printf("Total keylog data: %d bytes\n", totalKeylogBytes)

	if dsbCount == 0 {
		fmt.Println("\n❌ NO DSB blocks found! TLS keys are NOT embedded in the file.")
		fmt.Println("   Wireshark will NOT be able to decrypt TLS traffic automatically.")
	} else {
		fmt.Printf("\n✓ Found %d DSB block(s) with %d bytes of keylog data\n", dsbCount, totalKeylogBytes)
		fmt.Println("  Wireshark should be able to decrypt TLS traffic automatically.")
	}
}

func getBlockName(blockType uint32) string {
	switch blockType {
	case BlockTypeSectionHeader:
		return "Section Header Block"
	case BlockTypeInterfaceDescription:
		return "Interface Description Block"
	case BlockTypePacket:
		return "Packet Block (deprecated)"
	case BlockTypeSimplePacket:
		return "Simple Packet Block"
	case BlockTypeNameResolution:
		return "Name Resolution Block"
	case BlockTypeInterfaceStatistics:
		return "Interface Statistics Block"
	case BlockTypeEnhancedPacket:
		return "Enhanced Packet Block"
	case BlockTypeDecryptionSecrets:
		return "Decryption Secrets Block (DSB)"
	case BlockTypeCustomCanCopy:
		return "Custom Block (can copy)"
	case BlockTypeCustomNoCopy:
		return "Custom Block (no copy)"
	default:
		return "Unknown"
	}
}
