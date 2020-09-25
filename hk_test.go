// hk_test is a start at a decoder I was writing, which exhibited some problems.
// It also illustrates what a real decoder might look like.

package netshovel

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

var wg sync.WaitGroup

// HKStreamFactory generates HKStreams.
type HKStreamFactory struct {
	err *error
}

// New returns a new HKStream.
func (f *HKStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &HKStream{
		Stream: NewStream(net, transport),
		err:    f.err,
	}
	wg.Add(1)
	go stream.Decode(&wg)

	return stream
}

// HKStream represents half of a TCP Stream.
type HKStream struct {
	*Stream
	err *error
}

func (stream HKStream) Read(length int) (Utterance, error) {
	u, err := stream.Stream.Read(length)
	return u, err
}

// DisplayUtterance prints an unparsed TCP utterance
func (stream HKStream) DisplayUtterance(u Utterance) {
	fmt.Printf("Unparsed %v:%v → %v:%v\n",
		stream.Net.Src().String(), stream.Transport.Src().String(),
		stream.Net.Dst().String(), stream.Transport.Dst().String(),
	)
	fmt.Println(u.Data.Hexdump())
}

// Display prints as much about an HKPacket as we are able to determine.
func (stream HKStream) Display(pkt HKPacket) {
	out := new(strings.Builder)

	fmt.Fprintf(out, "HK %v:%v → %v:%v\n",
		stream.Net.Src().String(), stream.Transport.Src().String(),
		stream.Net.Dst().String(), stream.Transport.Dst().String(),
	)
	out.WriteString(pkt.Describe())
	fmt.Println(out.String())
}

// Decode decodes all data from the stream.
func (stream HKStream) Decode(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		utterance, err := stream.Read(2)
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println(err)
			return
		}

		// Was it actually HK?
		if utterance.Data.String("DROP") != "HK" {
			u, err := stream.Read(-1)
			if err != nil {
				log.Println(err)
				return
			}

			if utterance.When != u.When {
				stream.DisplayUtterance(utterance)
				utterance = u
				*stream.err = fmt.Errorf("Short length on non-HK packet, and a different utterance was returned")
			} else {
				utterance.Data = utterance.Data.Append(u.Data)
			}
			if utterance.Data.Length() < 10 {
				*stream.err = fmt.Errorf("Short length on non-HK packet")
				return
			}
			stream.DisplayUtterance(utterance)
			continue
		}

		pkt := NewHKPacket(utterance)
		if err := pkt.Decode(stream); err != nil {
			log.Println(err)
			return
		}
		stream.Display(pkt)
	}
}

// NewHKPacket returns a shiny new HKPacket.
func NewHKPacket(u Utterance) HKPacket {
	pkt := HKPacket{
		Packet: NewPacket(),
	}
	pkt.Payload = u.Data
	pkt.When = u.When
	return pkt
}

// HKPacket is a single HK packet.
type HKPacket struct {
	Packet
}

// Decode from a readable
func (pkt *HKPacket) Decode(stream HKStream) error {
	header, err := stream.Read(9)
	if err != nil {
		return err
	}
	pkt.Payload = header.Data

	unknown, _ := pkt.Uint32BE("unknown")
	length, _ := pkt.Uint32BE("length")
	opcode, _ := pkt.Uint8("opcode")
	pkt.Opcode = int(opcode)

	if unknown != 0 {
		return fmt.Errorf("unknown header was actually %d", unknown)
	}
	if length > 100 {
		return fmt.Errorf("Length too big: %d", length)
	}

	body, err := stream.Read(int(length - 9 - 2))
	if err != nil {
		return err
	}
	pkt.Payload = body.Data

	subcode, _ := pkt.Uint8("subcode")
	if subcode != 0 {
		return fmt.Errorf("Subcode not zero: %d", subcode)
	}
	pkt.SetString("Payload", pkt.Payload.String("DROP"))

	switch pkt.Opcode {
	case 7:
		pkt.Description = "Keepalive"
	}

	return nil
}

func TestHK(t *testing.T) {
	factory := HKStreamFactory{err: new(error)}
	streamPool := tcpassembly.NewStreamPool(&factory)
	assembler := tcpassembly.NewAssembler(streamPool)
	ShovelFile("testdata/hk.pcap", assembler)
	assembler.FlushAll()
	wg.Wait()

	if *factory.err != nil {
		t.Error(*factory.err)
	}
}
