package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
	"github.com/dirtbags/netshovel/gapstring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var StreamWG sync.WaitGroup

type WriteAtCloser interface {
	io.WriterAt
	io.WriteCloser
}

type Utterance struct {
	When time.Time
	Data gapstring.GapString
}

type StreamFactory struct {}

type Stream struct {
	Net, Transport gopacket.Flow
	conversation chan Utterance
	done chan bool
	pending Utterance
}

func (f *StreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &Stream{
		Net: net,
		Transport: transport,
		conversation: make(chan Utterance, 100),
	}
	StreamWG.Add(1)
	go stream.Run(StreamWG)
	
	return stream
}

func (stream *Stream) Reassembled(rs []tcpassembly.Reassembly) {
	// XXX: How do we send timestamps?
	ret := Utterance{
		When: rs[0].Seen,
	}
	for _, r := range rs {
		if r.Skip > 0 {
			ret.Data = ret.Data.AppendGap(r.Skip)
		}
		ret.Data = ret.Data.AppendBytes(r.Bytes)
	}
	
	// Throw away utterances with no data (SYN, ACK, FIN, &c)
	if ret.Data.Length() > 0 {
		stream.conversation <- ret
	}
}

func (stream *Stream) ReassemblyComplete() {
	close(stream.conversation)
}

func (stream *Stream) Read(length int) (Utterance, error) {
	if length > 0x100000 {
		log.Fatalf("FATAL: Trying to read 0x%x octets", length)
	}

	// Special case: length=-1 means "give me the next utterance"
	if length == -1 {
		if stream.pending.Data.Length() > 0 {
			ret := stream.pending
			stream.pending.Data = gapstring.GapString{}
			return ret, nil
		} else {
			ret, more := <- stream.conversation
			if ! more {
				return ret, io.EOF
			}
			return ret, nil
		}
	}

	// Pull in utterances until we have enough data.
	// .When will always be the timestamp on the last received utterance
	for stream.pending.Data.Length() < length {
		u, more := <- stream.conversation
		if ! more {
			break
		}
		stream.pending.Data = stream.pending.Data.Append(u.Data)
		stream.pending.When = u.When
	}

	// If we got nothing, it's the end of the stream
	if stream.pending.Data.Length() == 0 {
		return Utterance{}, io.EOF
	}
	
	ret := Utterance{
		Data: stream.pending.Data.Slice(0, length),
		When: stream.pending.When,
	}
	stream.pending.Data = stream.pending.Data.Slice(length, stream.pending.Data.Length())
	return ret, nil
}

func (stream *Stream) Describe(pkt Packet) string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "%v:%v → %v:%v\n",
		stream.Net.Src().String(), stream.Transport.Src().String(),
    stream.Net.Dst().String(), stream.Transport.Dst().String()
  )
  out.writeString(pkt.Describe())
	return out.String()
}

func (stream *Stream) Run(wg sync.WaitGroup) {
	defer wg.Done()
	for {
		pkt, err := stream.BuildPacket()
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println(err) // XXX: Print out 4-tuple identifying this stream
			return
		}
		
		fmt.Println(stream.Describe(pkt))
	}
}

func (stream *Stream) BuildPacket() (Packet, error) {
	pkt := NewPacket()
	
	utterance, err := stream.Read(-1)
	if err != nil {
		return pkt, err
	}
	
	pkt.Payload = utterance.Data
	pkt.When = utterance.When
	return pkt, nil
}
