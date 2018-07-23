package main

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/dirtbags/netshovel"
)

var threads int
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
	threads += 1
	wg.Add(1)
	go stream.Decode(wg)

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

func (stream SimpleStream) Decode(wg sync.WaitGroup) {
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
	threads -= 1
	wg.Done()
}

func main() {
	threads = 0
	netshovel.Shovel(&SimpleStreamFactory{})

	// XXX: ZOMG WHY
	for threads > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	//wg.Wait()
}
