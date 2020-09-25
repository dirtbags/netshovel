package netshovel

import (
	"strings"
	"testing"

	"github.com/dirtbags/netshovel/gapstring"
)

// BUG(neale): The DescribeHeader test is too simplistic.
func TestHeaders(t *testing.T) {
	pkt := NewPacket()
	pkt.Payload = gapstring.OfBytes([]byte{0, 1, 0, 1, 42, 0xff, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 64})

	a, err := pkt.Uint16LE("le")
	if err != nil {
		t.Error(err)
	}
	if a != 0x0100 {
		t.Error("Uint16LE", a)
	}

	b, err := pkt.Uint16BE("be")
	if err != nil {
		t.Error(err)
	}
	if b != 0x0001 {
		t.Error("Uint16BE", b)
	}

	fnord, err := pkt.Uint8("fnord")
	if err != nil {
		t.Error(err)
	}
	if fnord != 42 {
		t.Error("Uint8", fnord)
	}

	biggun, err := pkt.Uint32BE("biggun")
	if err != nil {
		t.Error(err)
	}
	if biggun != 0xff000001 {
		t.Error("biggun", biggun)
	}

	bignum, err := pkt.Uint64BE("bignum")
	if err != nil {
		t.Error(err)
	}
	if bignum != 64 {
		t.Error("bignum", bignum)
	}

	desc := pkt.DescribeHeader()
	lines := strings.Split(desc, "\n")
	if len(lines) != 14 {
		t.Error(desc)
	}
}
