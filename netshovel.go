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


func Shovel(factory tcpassembly.StreamFactory) {
	verbose := flag.Bool("verbose", false, "Write lots of information out")
	flag.Parse()
	
	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)
	
	for _, fn := range flag.Args() {
		handle, err := pcap.OpenOffline(fn)
		if err != nil {
			log.Fatal(err)
		}
		
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packets := packetSource.Packets()
		npackets := 0
		for packet := range packets {
			if packet == nil {
				break
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			npackets += 1
		}
		log.Println("npackets", npackets)
	}
	assembler.FlushAll()
	goRoutines.Wait()
}
