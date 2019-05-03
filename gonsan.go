package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func view(p packetInfo) {
	fmt.Println(p.String())
}

func getPacketSourceFromPcap(pcapFile *string) (*gopacket.PacketSource, func(), error) {
	var (
		handle *pcap.Handle
		err    error
	)
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		return nil, nil, err
	}
	return gopacket.NewPacketSource(handle, layers.LinkTypeEthernet), handle.Close, nil
}

func getPacketSourceFromIF(ifname *string) (*gopacket.PacketSource, func(), error) {
	var (
		handle      *pcap.Handle
		err         error
		snaplen     int32         = 1024
		promiscuous bool          = false
		timeout     time.Duration = 30 * time.Second
	)
	handle, err = pcap.OpenLive(*ifname, snaplen, promiscuous, timeout)
	if err != nil {
		return nil, nil, err
	}
	return gopacket.NewPacketSource(handle, layers.LinkTypeEthernet), handle.Close, nil
}

func main() {
	pcapFile := flag.String("r", "", "read pcap")
	//ifname := flag.String("i", "", "read network interface name")
	samplingRate := flag.Int("s", 1, "sampling rate")
	flag.Parse()

	var (
		packetSource *gopacket.PacketSource
		err          error
	)

	if *pcapFile == "" {
		log.Fatal(errors.New("set read pcap"))
	}
	packetSource, handleclose, err := getPacketSourceFromPcap(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handleclose()

	cpus := runtime.NumCPU()
	ch := make(chan packetInfo, cpus)
	wg := &sync.WaitGroup{}
	sampleCounter := *samplingRate

	for packet := range packetSource.Packets() {
		if sampleCounter == *samplingRate {
			wg.Add(1)
			go analyze(&packet, &ch)
			go func() {
				defer wg.Done()
				view(<-ch)
			}()
			sampleCounter = 1
		} else {
			sampleCounter++
		}
	}
	wg.Wait()
}
