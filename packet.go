package netshovel

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/dirtbags/netshovel/gapstring"
)

// ShortError is returned by convenience methods that are unable to get enough data
type ShortError struct {
	Wanted    int // How many bytes you needed
	Available int // How many bytes were available
}

func (e *ShortError) Error() string {
	return fmt.Sprintf("Short read: wanted %d of %d available", e.Wanted, e.Available)
}

// MissingError is returned by convenience methods that are unable to operate on gaps in data
type MissingError struct {
}

func (e *MissingError) Error() string {
	return "Operation on missing bytes"
}

// A Key,Value Pair
type namedField struct {
	key, value string
}

// An application protocol header field
type headerField struct {
	name  string
	bits  int
	value interface{}
	order binary.ByteOrder
}

// A Packet represents a single application-layer packet
//
// The Packet struct provides helper methods to assist
// with
// reverse-engineering new protocols
// and
// documenting header structure.
type Packet struct {
	Opcode      int
	Description string
	When        time.Time
	Payload     gapstring.GapString
	header      []headerField
	fields      []namedField
}

var never = time.Unix(0, 0)

// NewPacket returns a new packet
func NewPacket() Packet {
	return Packet{
		Opcode:      -1,
		Description: "Undefined",
		When:        never,
		Payload:     gapstring.GapString{},
		header:      []headerField{},
		fields:      []namedField{},
	}
}

// DescribeType returns a string with timestamp, opcode, and description of this packet
func (pkt *Packet) DescribeType() string {
	return fmt.Sprintf(
		"  %s Opcode %d: %s",
		pkt.When.UTC().Format(time.RFC3339Nano),
		pkt.Opcode,
		pkt.Description,
	)
}

// DescribeFields returns a multi-line string describing fields in this packet
func (pkt *Packet) DescribeFields() string {
	out := new(strings.Builder)
	for _, f := range pkt.fields {
		fmt.Fprintf(out, "    %s: %s\n", f.key, f.value)
	}
	return out.String()
}

func center(s string, w int) string {
	if len(s) > w {
		s = s[0:w-3] + "…"
	}
	return fmt.Sprintf("%*s", -w, fmt.Sprintf("%*s", (w+len(s))/2, s))
}

// DescribeHeader returns a multi-line string describing this packet's header structure
func (pkt *Packet) DescribeHeader() string {
	out := new(strings.Builder)
	fmt.Fprintln(out, " 0                               1                            ")
	fmt.Fprintln(out, " mo0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f")

	bitOffset := 0
	for _, f := range pkt.header {
		bits := f.bits
		for bits > 0 {
			if bitOffset == 0 {
				fmt.Fprintln(out, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
			}

			linebits := bits
			if linebits+bitOffset > 0x20 {
				linebits = 0x20 - bitOffset
			}

			// Generate centered string
			// TODO: right-align value, center name
			nameval := fmt.Sprintf("%s (0x%x)", f.name, f.value)
			fmt.Fprintf(out, "|%s", center(nameval, linebits*2-1))

			bitOffset += linebits
			bits -= linebits
			if linebits == 0x20 {
				fmt.Fprintln(out, "|")
				bitOffset = 0
			}
		}
	}
	if bitOffset > 0 {
		fmt.Fprintln(out, "|")
	}
	fmt.Fprintln(out, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	return out.String()
}

// Describe returns a multi-line string describing this packet
//
// This shows the timestamp, opcode, description, and hex dump.
// If you set any values, those are displayed in the order they were set.
//
// This will quickly get unweildy, especially for large conversations.
// You are encouraged to implement your own Describe() method.
func (pkt *Packet) Describe() string {
	out := new(strings.Builder)

	fmt.Fprintln(out, pkt.DescribeType())
	fmt.Fprint(out, pkt.DescribeFields())
	fmt.Fprint(out, pkt.DescribeHeader())
	fmt.Fprint(out, pkt.Payload.Hexdump())
	return out.String()
}

// Set a value
//
// This is intended to be used to note debugging information
// that you'd like to see on each packet.
func (pkt *Packet) Set(key, value string) {
	pkt.fields = append(pkt.fields, namedField{key, value})
}

// SetString sets a string value, displaying its Go string representation
func (pkt *Packet) SetString(key, value string) {
	pkt.Set(key, fmt.Sprintf("%#v", value))
}

// SetInt sets an int value, displaying its decimal and hexadecimal representations
func (pkt *Packet) SetInt(key string, value int) {
	pkt.Set(key, fmt.Sprintf("%d == 0x%x", value, value))
}

// SetUint sets an unsigned int value, displaying its decimal and hexadecimal representations
func (pkt *Packet) SetUint(key string, value uint) {
	pkt.Set(key, fmt.Sprintf("%d == 0x%x", value, value))
}

// SetUint32 sets an Unt32 value, displaying its decimal and 0-padded hexadecimal representations
func (pkt *Packet) SetUint32(key string, value uint32) {
	pkt.Set(key, fmt.Sprintf("%d == 0x%04x", value, value))
}

// SetBytes sets a []byte value, displaying the hex encoding of the bytes
func (pkt *Packet) SetBytes(key string, value []byte) {
	pkt.Set(key, hex.EncodeToString(value))
}

// SetGapString sets a GapString value, displaying the hex encoding and runes encoding (like a hex dump)
func (pkt *Packet) SetGapString(key string, value gapstring.GapString) {
	pkt.Set(key, fmt.Sprintf("%s  %s", value.HexString(), value.Runes()))
}

// Peel octets bytes off of the Payload, returning those bytes
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

// AddHeaderField adds a field to the header field description
func (pkt *Packet) AddHeaderField(order binary.ByteOrder, name string, bits int, value interface{}) {
	h := headerField{
		name:  name,
		bits:  bits,
		value: value,
		order: order,
	}
	pkt.header = append(pkt.header, h)
}

// Peel from Payload an unsigned integer of size bits, adding it to the header field list
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

// Uint64LE peels off a uint64, little-endian
func (pkt *Packet) Uint64LE(name string) (uint64, error) {
	value, err := pkt.readUint(binary.LittleEndian, 64, name)
	if err != nil {
		return 0, err
	}
	return value.(uint64), err
}

// Uint32LE peels off a uint32, little-endian
func (pkt *Packet) Uint32LE(name string) (uint32, error) {
	value, err := pkt.readUint(binary.LittleEndian, 32, name)
	if err != nil {
		return 0, err
	}
	return value.(uint32), err
}

// Uint16LE peels off a uint16, little-endian
func (pkt *Packet) Uint16LE(name string) (uint16, error) {
	value, err := pkt.readUint(binary.LittleEndian, 16, name)
	if err != nil {
		return 0, err
	}
	return value.(uint16), err
}

// Uint64BE peels off a uint64, big-endian
func (pkt *Packet) Uint64BE(name string) (uint64, error) {
	value, err := pkt.readUint(binary.BigEndian, 64, name)
	if err != nil {
		return 0, err
	}
	return value.(uint64), err
}

// Uint32BE peels off a uint32, big-endian
func (pkt *Packet) Uint32BE(name string) (uint32, error) {
	value, err := pkt.readUint(binary.BigEndian, 32, name)
	if err != nil {
		return 0, err
	}
	return value.(uint32), err
}

// Uint16BE peels off a uint16, big-endian
func (pkt *Packet) Uint16BE(name string) (uint16, error) {
	value, err := pkt.readUint(binary.BigEndian, 16, name)
	if err != nil {
		return 0, err
	}
	return value.(uint16), err
}

// Uint8 peels off a uint8 (aka byte)
func (pkt *Packet) Uint8(name string) (uint8, error) {
	value, err := pkt.readUint(binary.BigEndian, 8, name)
	if err != nil {
		return 0, err
	}
	return value.(uint8), err
}
