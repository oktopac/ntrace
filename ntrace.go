package main

import (
	"flag"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet")
var bufferedPerConnection = flag.Int("connection_max_buffer", 0, `
Max packets to buffer for a single connection before skipping over a gap in data
and continuing to stream the connection after the buffer.  If zero or less, this
is infinite.`)

var bufferedTotal = flag.Int("total_max_buffer", 0, `
Max packets to buffer total before skipping over gaps in connections and
continuing to stream connection data.  If zero or less, this is infinite`)

var flushAfter = flag.String("flush_after", "10s", `
Connections which have buffered packets (they've gotten packets out of order and
are waiting for old packets to fill the gaps) are flushed after they're this old
(their oldest gap is skipped).  Any string parsed by time.ParseDuration is
acceptable here`)

var packetCount = flag.Int("c", -1, `
Quit after processing this many packets, flushing all currently buffered
connections.  If negative, this is infinite`)

// simpleStreamFactory implements tcpassembly.StreamFactory
type statsStreamFactory struct{}

// statsStream will handle the actual decoding of stats requests.
type statsStream struct {
	net, transport                      gopacket.Flow
	bytes, packets, outOfOrder, skipped int64
	start, end                          time.Time
	sawStart, sawEnd                    bool
}

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func (factory *statsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	log.Printf("new stream %v:%v started", net, transport)
	s := &statsStream{
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	s.end = s.start
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return s
}

// Reassembled is called whenever new packet data is available for reading.
// Reassembly objects contain stream data IN ORDER.
func (s *statsStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytes += int64(len(reassembly.Bytes))
		s.packets += 1
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}
}

// ReassemblyComplete is called when the TCP assembler believes a stream has
// finished.
func (s *statsStream) ReassemblyComplete() {
	diffSecs := float64(s.end.Sub(s.start)) / float64(time.Second)
	log.Printf("Reassembly of stream %v:%v complete - start:%v end:%v bytes:%v packets:%v ooo:%v bps:%v pps:%v skipped:%v",
		s.net, s.transport, s.start, s.end, s.bytes, s.packets, s.outOfOrder,
		float64(s.bytes)/diffSecs, float64(s.packets)/diffSecs, s.skipped)
}

func main() {
	defer util.Run()()

	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Fatal("invalid flush duration: ", *flushAfter)
	}

	log.Printf("starting capture on interface %q", *iface)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	// Set up assembly
	streamFactory := &statsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = *bufferedPerConnection
	assembler.MaxBufferedPagesTotal = *bufferedTotal

	log.Println("reading in packets")

	// We use a DecodingLayerParser here instead of a simpler PacketSource.
	// This approach should be measurably faster, but is also more rigid.
	// PacketSource will handle any known type of packet safely and easily,
	// but DecodingLayerParser will only handle those packet types we
	// specifically pass in.  This trade-off can be quite useful, though, in
	// high-throughput situations.
	// var eth layers.Ethernet
	// var dot1q layers.Dot1Q
	// var ip4 layers.IPv4
	// var ip6 layers.IPv6
	// var ip6extensions layers.IPv6ExtensionSkipper
	// var tcp layers.TCP
	// var payload gopacket.Payload
	//
	// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
	// 	&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &payload)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// decoded := make([]gopacket.LayerType, 0, 4)

	// nextFlush := time.Now().Add(flushDuration / 2)

	var byteCount int64
	start := time.Now()

	ticker := time.Tick(flushDuration)
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			foundNetLayer := false
			var netFlow gopacket.Flow
			for _, layer := range packet.Layers() {
				switch layer.LayerType() {
				case layers.LayerTypeIPv4:
					netFlow = packet.NetworkLayer().NetworkFlow()
					foundNetLayer = true
				case layers.LayerTypeIPv6:
					netFlow = packet.NetworkLayer().NetworkFlow()
					foundNetLayer = true
				case layers.LayerTypeTCP:
					if foundNetLayer {
						tcp := packet.TransportLayer().(*layers.TCP)
						assembler.AssembleWithTimestamp(netFlow, tcp, packet.Metadata().CaptureInfo.Timestamp)
					} else {
						log.Println("could not find IPv4 or IPv6 layer, inoring")
					}
				}
			}
		case <-ticker:
			stats, _ := handle.Stats()
			log.Printf("flushing all streams that haven't seen packets in the last 2 minutes, pcap stats: %+v", stats)
			assembler.FlushOlderThan(time.Now().Add(flushDuration))
		}

	}

	assembler.FlushAll()
	log.Printf("processed %d bytes in %v", byteCount, time.Since(start))
}
