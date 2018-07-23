package main

import (
	"github.com/dirtbags/netshovel"
)

struct SimpleStreamFactory {
	netshovel.Factory
}

struct SimpleStream {
	netshovel.Stream
}

func (f *SimpleStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	ret = SimpleStream{}
	ret.Stream = f.Factory.New(net, transport)
}

struct SimplePacket {
	netshovel.Packet
}

func main() {
	netshovel.Shovel(SimpleFactory)
}
