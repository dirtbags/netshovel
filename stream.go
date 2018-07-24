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

// A File and the path where it lives
type NamedFile struct {
	*os.File
	Name string
}

// An atomic communication within a Stream
//
// Streams consist of a string of Utterances.
// Each utterance has associated data, and a time stamp.
//
// Typically these line up with what crosses the network,
// but bear in mind that TCP is a streaming protocol,
// so don't rely on Utterances alone to separate Application-layer packets.
type Utterance struct {
	When time.Time
	Data gapstring.GapString
}

// A Stream is one half of a two-way conversation
type Stream struct {
	Net, Transport gopacket.Flow
	conversation chan Utterance
	pending Utterance
}

// Return a newly-built Stream
//
// You should embed Stream into your own Application protocol stream struct.
// Use this to initialize the internal stuff netshovel needs.
func NewStream(net, transport gopacket.Flow) Stream {
	return Stream{
		Net: net,
		Transport: transport,
		conversation: make(chan Utterance, 100),
	}
}

// Called by the TCP assembler when an Utterance can be built
func (stream *Stream) Reassembled(rs []tcpassembly.Reassembly) {
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

// Called by the TCP assemble when the Stream is closed
func (stream *Stream) ReassemblyComplete() {
	close(stream.conversation)
}

// Read an utterance of a particular size
//
// If you pass in a length of -1,
// this returns utterances as they appear in the conversation.
//
// At first, your decoder will probably want to use a length of -1:
// this will give you a sense of how the conversation works.
// When you begin to understand the structure of your protocol,
// change this to a positive integer,
// so that if you have a large application-layer packet,
// or multiple application-layer packets in a single transport-layer packet,
// your decoder handles it properly.
func (stream *Stream) Read(length int) (Utterance, error) {
	// This probably indicates a problem, but we assume you know what you're doing
	if length == 0 {
		return Utterance{}, nil
	}
	
	// Special case: length=-1 means "give me the next utterance"
	if length == -1 {
		var ret Utterance
		var err error = nil
		if stream.pending.Data.Length() > 0 {
			ret = stream.pending
			stream.pending.Data = gapstring.GapString{}
		} else {
			r, more := <- stream.conversation
			if ! more {
				err = io.EOF
			}
			ret = r
		}
		return ret, err
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

	pendingLen := stream.pending.Data.Length()
	// If we got nothing, it's the end of the stream
	if pendingLen == 0 {
		return Utterance{}, io.EOF
	}
	
	sliceLen := length
	if sliceLen > pendingLen {
		sliceLen = pendingLen
	}
	ret := Utterance{
		Data: stream.pending.Data.Slice(0, sliceLen),
		When: stream.pending.When,
	}
	stream.pending.Data = stream.pending.Data.Slice(sliceLen, pendingLen)
	return ret, nil
}

// Return a string description of a packet
//
// This just prefixes our source and dest IP:Port to pkt.Describe()
func (stream *Stream) Describe(pkt Packet) string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "%v:%v → %v:%v\n",
		stream.Net.Src().String(), stream.Transport.Src().String(),
    stream.Net.Dst().String(), stream.Transport.Dst().String(),
  )
  out.WriteString(pkt.Describe())
	return out.String()
}

// Return a newly-created, truncated file
//
// This function creates consistently-named files,
// which include a timestamp,
// and URL-escaped full path to the file.
//
// Best practice is to pass in as full a path as you can find,
// including drive letters and all parent directories.
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
