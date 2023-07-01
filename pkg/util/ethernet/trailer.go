package ethernet

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

// EthernetBroadcast is the broadcast MAC address used by Ethernet.
// var EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// EthernetWithTrailer is the layer for Ethernet frame headers.
type EthernetWithTrailer struct {
	layers.BaseLayer
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   layers.EthernetType
	// Length is only set if a length field exists within this header.  Ethernet
	// headers follow two different standards, one that uses an EthernetType, the
	// other which defines a length the follows with a LLC header (802.3).  If the
	// former is the case, we set EthernetType and Length stays 0.  In the latter
	// case, we set Length and EthernetType = EthernetTypeLLC.
	Length  uint16
	Trailer []byte
}

// LayerType returns LayerTypeEthernet
func (e *EthernetWithTrailer) LayerType() gopacket.LayerType { return layers.LayerTypeEthernet }

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (e *EthernetWithTrailer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if len(e.DstMAC) != 6 {
		return fmt.Errorf("invalid dst MAC: %v", e.DstMAC)
	}
	if len(e.SrcMAC) != 6 {
		return fmt.Errorf("invalid src MAC: %v", e.SrcMAC)
	}
	payload := b.Bytes()
	bytes, err := b.PrependBytes(14)
	if err != nil {
		return err
	}
	copy(bytes, e.DstMAC)
	copy(bytes[6:], e.SrcMAC)
	if e.Length != 0 || e.EthernetType == layers.EthernetTypeLLC {
		if opts.FixLengths {
			e.Length = uint16(len(payload))
		}
		if e.EthernetType != layers.EthernetTypeLLC {
			return fmt.Errorf("ethernet type %v not compatible with length value %v", e.EthernetType, e.Length)
		} else if e.Length > 0x0600 {
			return fmt.Errorf("invalid ethernet length %v", e.Length)
		}
		binary.BigEndian.PutUint16(bytes[12:], e.Length)
	} else {
		binary.BigEndian.PutUint16(bytes[12:], uint16(e.EthernetType))
	}
	length := len(b.Bytes())
	if length < 60 {
		// Pad out to 60 bytes.
		padding, err := b.AppendBytes(60 - length)
		if err != nil {
			return err
		}
		copy(padding, lotsOfZeros[:])
	}

	//todo: find a way to put the trailer here
	trailer, err := b.AppendBytes(len(e.Trailer))
	if err != nil {
		return err
	}
	copy(trailer, e.Trailer)
	// todo: some of this gets gobbled up as framecheck sequence, putting a 4 byte 0 in the trailer to avoid that
	checksum, err := b.AppendBytes(4)
	if err != nil {
		return err
	}
	copy(checksum, lotsOfZeros[:])
	return nil
}

var lotsOfZeros [1024]byte
