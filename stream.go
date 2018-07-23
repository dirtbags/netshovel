package netshovel

import (
	"fmt"
	"io"
	"os"
	"net/url"
	"strings"
	"time"
	"github.com/dirtbags/netshovel/gapstring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type NamedFile struct {
	*os.File
	Name string
}

type Utterance struct {
	When time.Time
	Data gapstring.GapString
}

type Stream struct {
	Net, Transport gopacket.Flow
	conversation chan Utterance
	pending Utterance
}

func NewStream(net, transport gopacket.Flow) Stream {
	return Stream{
		Net: net,
		Transport: transport,
		conversation: make(chan Utterance, 100),
	}
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
    stream.Net.Dst().String(), stream.Transport.Dst().String(),
  )
  out.WriteString(pkt.Describe())
	return out.String()
}

func (stream *Stream) CreateFile(when time.Time, path string) (NamedFile, error) {
  name := fmt.Sprintf(
		"xfer/%s,%sp%s,%sp%s,%s",
		when.UTC().Format(time.RFC3339Nano),
		stream.Net.Src().String(), stream.Transport.Src().String(),
    stream.Net.Dst().String(), stream.Transport.Dst().String(),
		url.PathEscape(path),
	)
  f, err := os.Create(name)
  outf := NamedFile{
  	File: f,
  	Name: name,
  }
  return outf, err
}
