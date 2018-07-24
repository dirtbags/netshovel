package netshovel

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"github.com/dirtbags/netshovel/gapstring"
)

type ShortError struct {
	wanted, available int
}
func (e *ShortError) Error() string {
	return fmt.Sprintf("Short read: wanted %d of %d available", e.wanted, e.available)
}

type MissingError struct {
}
func (e *MissingError) Error() string {
	return "Operation on missing bytes"
}

type PacketFactory func()Packet

type NamedField struct {
	key, value string
}

type HeaderField struct {
	name string
	bits int
	value interface{}
	order binary.ByteOrder
}

type Packet struct {
	Name string
	Opcode int
	Description string
	When time.Time
	Payload gapstring.GapString
	Header []HeaderField
	Fields []NamedField
}

var never = time.Unix(0, 0)

func NewPacket() Packet {
	return Packet{
		Opcode: -1,
		Description: "Undefined",
		When: never,
		Payload: gapstring.GapString{},
		Header: []HeaderField{},
		Fields: []NamedField{},
	}
}

func (pkt *Packet) Describe() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "  %s Opcode %d: %s\n",
	  pkt.When.UTC().Format(time.RFC3339Nano),
		pkt.Opcode,
		pkt.Description,
	)
	
	for _, f := range(pkt.Fields) {
		fmt.Fprintf(out, "    %s: %s\n", f.key, f.value)
	}
	fmt.Fprint(out, pkt.Payload.Hexdump())
	return out.String()
}


func (pkt *Packet) Set(key, value string) {
	pkt.Fields = append(pkt.Fields, NamedField{key, value})
}

func (pkt *Packet) SetString(key, value string) {
	pkt.Set(key, fmt.Sprintf("%#v", value))
}

func (pkt *Packet) SetInt(key string, value int) {
	pkt.Set(key, fmt.Sprintf("%d == 0x%x", value, value))
}

func (pkt *Packet) SetUint(key string, value uint) {
	pkt.Set(key, fmt.Sprintf("%d == 0x%x", value, value))
}

func (pkt *Packet) SetUint32(key string, value uint32) {
	pkt.Set(key, fmt.Sprintf("%d == 0x%04x", value, value))
}

func (pkt *Packet) SetBytes(key string, value []byte) {
	pkt.Set(key, hex.EncodeToString(value))
}

func (pkt *Packet) SetGapString(key string, value gapstring.GapString) {
	pkt.Set(key, fmt.Sprintf("%s  %s", value.HexString(), value.Runes()))
}

func (pkt *Packet) Peel(octets int) ([]byte, error) {
	pllen := pkt.Payload.Length()
	if octets > pllen {
		return nil, &ShortError{octets, pllen}
	}
	buf := pkt.Payload.Slice(0, octets)
	if buf.Missing() > 0 {
		return nil, &MissingError{}
	}

	pkt.Payload = pkt.Payload.Slice(octets, pkt.Payload.Length())
	b := buf.Bytes()
	return b, nil
}

func (pkt *Packet) AddHeaderField(order binary.ByteOrder, name string, bits int, value interface{}) {
	h := HeaderField{
		name: name,
		bits: bits,
		value: value,
		order: order,
	}
	pkt.Header = append(pkt.Header, h)
}

func (pkt *Packet) readUint(order binary.ByteOrder, bits int, name string) (interface{}, error) {
	switch bits {
	case 8:
	case 16:
	case 32:
	case 64:
	default:
	  return 0, fmt.Errorf("Weird number of bits: %d", bits)
	}
	
	octets := bits >> 3
	b, err := pkt.Peel(octets)
	if err != nil {
		return 0, err
	}
	
	var value interface{}
	switch bits {
	case 8:
	  value = b[0]
	case 16:
		value = order.Uint16(b)
	case 32:
	  value = order.Uint32(b)
	case 64:
	  value = order.Uint64(b)
	}
	pkt.AddHeaderField(order, name, bits, value)
	
	return value, nil
}

func (pkt *Packet) Uint64LE(name string) (uint64, error) {
	value, err := pkt.readUint(binary.LittleEndian, 64, name)
	if err != nil {
		return 0, err
	}
	return value.(uint64), err
}

func (pkt *Packet) Uint32LE(name string) (uint32, error) {
	value, err := pkt.readUint(binary.LittleEndian, 32, name)
	if err != nil {
		return 0, err
	}
	return value.(uint32), err
}

func (pkt *Packet) Uint16LE(name string) (uint16, error) {
	value, err := pkt.readUint(binary.LittleEndian, 16, name)
	if err != nil {
		return 0, err
	}
	return value.(uint16), err
}

func (pkt *Packet) Uint64BE(name string) (uint64, error) {
	value, err := pkt.readUint(binary.BigEndian, 64, name)
	if err != nil {
		return 0, err
	}
	return value.(uint64), err
}

func (pkt *Packet) Uint32BE(name string) (uint32, error) {
	value, err := pkt.readUint(binary.BigEndian, 32, name)
	if err != nil {
		return 0, err
	}
	return value.(uint32), err
}

func (pkt *Packet) Uint16BE(name string) (uint16, error) {
	value, err := pkt.readUint(binary.BigEndian, 16, name)
	if err != nil {
		return 0, err
	}
	return value.(uint16), err
}

func (pkt *Packet) Uint8(name string) (uint8, error) {
	value, err := pkt.readUint(binary.BigEndian, 8, name)
	if err != nil {
		return 0, err
	}
	return value.(uint8), err
}

