package main

import (
	"fmt"
	"github.com/dirtbags/netshovel"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"io"
	"log"
	"strings"
	"sync"
)

var wg sync.WaitGroup

type SimpleStreamFactory struct {
}

type SimpleStream struct {
	netshovel.Stream
}

type SimplePacket struct {
	netshovel.Packet
}

func NewSimplePacket() SimplePacket {
	return SimplePacket{
		Packet: netshovel.NewPacket(),
	}
}

func (f *SimpleStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &SimpleStream{
		Stream: netshovel.NewStream(net, transport),
	}
	wg.Add(1)
	go stream.Decode(&wg)

	return stream
}

func (stream SimpleStream) Display(pkt SimplePacket) {
	out := new(strings.Builder)

	fmt.Fprintf(out, "Simple %v:%v → %v:%v\n",
		stream.Net.Src().String(), stream.Transport.Src().String(),
		stream.Net.Dst().String(), stream.Transport.Dst().String(),
	)
	out.WriteString(pkt.Describe())
	fmt.Println(out.String())
}

func (stream SimpleStream) Decode(wg *sync.WaitGroup) {
	for {
		pkt := NewSimplePacket()

		utterance, err := stream.Read(-1)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			break
		}

		pkt.Payload = utterance.Data
		pkt.When = utterance.When
		stream.Display(pkt)
	}
	wg.Done()
}

func main() {
	netshovel.Shovel(&SimpleStreamFactory{})
	wg.Wait()
}
