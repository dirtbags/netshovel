package netshovel

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"github.com/dirtbags/netshovel/gapstring"
)

type Packet struct {
	Opcode int
	Description string
	When time.Time
	Payload gapstring.GapString
	Fields map[string]string
}

var never = time.Unix(0, 0)

func NewPacket() Packet {
	return Packet{
		Opcode: -1,
		Description: "Undefined",
		When: never,
		Payload: gapstring.GapString{},
		Fields: map[string]string{},
	}
}

func (pkt *Packet) Name() string {
	return "Generic"
}

func (pkt *Packet) Describe() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "%s %s %d: %s\n",
	  pkt.When.UTC().Format(time.RFC3339Nano),
		pkt.Name(),
		pkt.Opcode,
		pkt.Description,
	)
	for _, k := range pkt.Keys() {
		fmt.Fprintf(out, "      %s: %s\n", k, pkt.Fields[k])
	}
	fmt.Fprint(out, pkt.Payload.Hexdump())
	return out.String()
}

func (pkt *Packet) Set(key, value string) {
	pkt.Fields[key] = value
}

func (pkt *Packet) Keys() []string{
	keys := make([]string, len(pkt.Fields))
	i := 0
	for k := range(pkt.Fields) {
		keys[i] = k
		i += 1
	}
	sort.Strings(keys)
	return keys
}
