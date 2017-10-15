// torch.go - sending out Ethernet CTP frames in ping-like manner
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to torch, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	log.SetFlags(0)
	intervalFlag := flag.String("i", "1s", "Interfal between frames")
	flag.Parse()
	if len(flag.Args()) < 1 {
		log.Fatal("no iterface specified")
	}
	iface := flag.Args()[0]
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if len(flag.Args()) == 2 {
		var err error
		dstMAC, err = net.ParseMAC(flag.Args()[1])
		if err != nil {
			log.Fatal(err)
		}
	}
	interval, err := time.ParseDuration(*intervalFlag)
	if err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive(iface, 0, true, -1*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	ethernetLayer := &layers.Ethernet{
		EthernetType: layers.EthernetTypeEthernetCTP,
		SrcMAC:       net.HardwareAddr{0xda, 0xda, 0xda, 0xda, 0xda, 0xda},
		DstMAC:       dstMAC,
	}

	seq := uint64(0)
	binSeq := make([]byte, 8)
	buffer := gopacket.NewSerializeBuffer()
	for {
		binary.BigEndian.PutUint64(binSeq, seq)
		gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			ethernetLayer,
			gopacket.Payload(binSeq),
		)
		err = handle.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Fatalf("unable to write packet: '%+v'", err)
		}
		log.Printf("sent frame #%v for %v [%x]", seq, dstMAC, binSeq)
		time.Sleep(interval)
		seq++
	}
}
