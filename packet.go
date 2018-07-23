package netshovel

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"github.com/dirtbags/netshovel/gapstring"
)

type PacketFactory func()Packet

type Field struct {
	key, value string
}

type Packet struct {
	Name string
	Opcode int
	Description string
	When time.Time
	Payload gapstring.GapString
	Fields []Field
}

var never = time.Unix(0, 0)

func NewPacket() Packet {
	return Packet{
		Opcode: -1,
		Description: "Undefined",
		When: never,
		Payload: gapstring.GapString{},
		Fields: []Field{},
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
	pkt.Fields = append(pkt.Fields, Field{key, value})
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
