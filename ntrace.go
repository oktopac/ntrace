package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func handlePacket(packet gopacket.Packet) {
	fmt.Println("I got a packet!")
}

func main() {

	if handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}
