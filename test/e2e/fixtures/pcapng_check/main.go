package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	sectionHeaderBlock     = 0x0a0d0d0a
	interfaceDescription   = 0x00000001
	enhancedPacketBlock    = 0x00000006
	decryptionSecretsBlock = 0x0000000a
	byteOrderMagic         = 0x1a2b3c4d
)

func main() {
	requireDSB := flag.Bool("require-dsb", false, "require at least one TLS decryption-secrets block")
	minPackets := flag.Int("min-packets", 1, "require at least this many enhanced packet blocks")
	flag.Parse()
	if flag.NArg() != 1 || *minPackets < 1 {
		fmt.Fprintln(os.Stderr, "usage: pcapng_check [--require-dsb] [--min-packets N] FILE")
		os.Exit(2)
	}

	counts, err := inspect(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if counts[sectionHeaderBlock] == 0 || counts[interfaceDescription] == 0 || counts[enhancedPacketBlock] == 0 {
		fmt.Fprintf(os.Stderr, "pcapng lacks required blocks: SHB=%d IDB=%d EPB=%d\n",
			counts[sectionHeaderBlock], counts[interfaceDescription], counts[enhancedPacketBlock])
		os.Exit(1)
	}
	if *requireDSB && counts[decryptionSecretsBlock] == 0 {
		fmt.Fprintln(os.Stderr, "pcapng lacks a TLS decryption-secrets block")
		os.Exit(1)
	}
	if counts[enhancedPacketBlock] < *minPackets {
		fmt.Fprintf(os.Stderr, "pcapng has too few packets: EPB=%d, require at least %d\n",
			counts[enhancedPacketBlock], *minPackets)
		os.Exit(1)
	}

	fmt.Printf("SHB=%d IDB=%d EPB=%d DSB=%d\n", counts[sectionHeaderBlock], counts[interfaceDescription],
		counts[enhancedPacketBlock], counts[decryptionSecretsBlock])
}

func inspect(path string) (map[uint32]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	header := make([]byte, 12)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, fmt.Errorf("read section header: %w", err)
	}
	if binary.LittleEndian.Uint32(header[:4]) != sectionHeaderBlock {
		return nil, fmt.Errorf("invalid pcapng section-header magic")
	}

	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(header[8:12]) == byteOrderMagic:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(header[8:12]) == byteOrderMagic:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("invalid pcapng byte-order magic")
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	counts := make(map[uint32]int)
	for {
		blockHeader := make([]byte, 8)
		_, err := io.ReadFull(file, blockHeader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read block header: %w", err)
		}

		blockType := order.Uint32(blockHeader[:4])
		blockLength := order.Uint32(blockHeader[4:8])
		if blockLength < 12 || blockLength%4 != 0 {
			return nil, fmt.Errorf("invalid block length %d for type 0x%08x", blockLength, blockType)
		}

		remainder := make([]byte, blockLength-8)
		if _, err := io.ReadFull(file, remainder); err != nil {
			return nil, fmt.Errorf("read block 0x%08x: %w", blockType, err)
		}
		if order.Uint32(remainder[len(remainder)-4:]) != blockLength {
			return nil, fmt.Errorf("block 0x%08x has mismatched trailing length", blockType)
		}
		counts[blockType]++
	}
	return counts, nil
}
