/*

Package netshovel provides utilities to assist in creating of application-layer protocol decoders.

examples/simple/simple.go contains a full decoder which does nothing but dump every utterance.
It can be used as a template for new work.

*/
package netshovel

import (
	"flag"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// Shovel handles dispatching of PCAP files from the command line.
// It's intended that you invoke this from your main function.
// This parses the command line arguments,
// and for each PCAP file specified on the command line,
// invokes a TCP assembler that sends streams to whatever is returned from factory.
func Shovel(factory tcpassembly.StreamFactory) {
	//verbose := flag.Bool("verbose", false, "Write lots of information out")
	flag.Parse()

	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, fn := range flag.Args() {
		ShovelFile(fn, assembler)
	}

	assembler.FlushAll()
}

// ShovelFile shovels a single file.
// You must call assembler.FlushAll() at the end of this!
func ShovelFile(filename string, assembler *tcpassembly.Assembler) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for packet := range packets {
		if packet == nil {
			break
		}
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			continue
		}
		tcp := packet.TransportLayer().(*layers.TCP)
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
}
