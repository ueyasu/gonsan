package analyze

import (
	"fmt"
	"log"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func view(p packetInfo) {
	fmt.Println(p.String())
}

func getPacketSourceFromPcap(pcapFile *string) (*gopacket.PacketSource, func(), error) {
	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		return nil, nil, err
	}
	return gopacket.NewPacketSource(handle, layers.LinkTypeEthernet), handle.Close, nil
}

func getPacketSourceFromIF(ifname *string) (*gopacket.PacketSource, func(), error) {
	handle, err := pcap.OpenLive(*ifname, 1600, true,  pcap.BlockForever)
	if err != nil {
		return nil, nil, err
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()), handle.Close, nil
}

func ReadPcap(pcapFile *string, samplingRate *int) {
	packetSource, handleclose, err := getPacketSourceFromPcap(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handleclose()
	analyzePacketSource(packetSource, samplingRate)
}

func ReadIF(ifname *string, samplingRate *int) {
	packetSource, handleclose, err := getPacketSourceFromIF(ifname)
	if err != nil {
		log.Fatal(err)
	}
	defer handleclose()
	analyzePacketSource(packetSource, samplingRate)
}

func analyzePacketSource(packetSource *gopacket.PacketSource, samplingRate *int) {
	cpus := runtime.NumCPU()
	ch := make(chan packetInfo, cpus)
	wg := &sync.WaitGroup{}
	sampleCounter := *samplingRate

	go func() {
		for true {
			view(<-ch)
			wg.Done()
		}
	}()

	for packet := range packetSource.Packets() {
		if sampleCounter == *samplingRate {
			wg.Add(1)
			go analyze(&packet, &ch)
			sampleCounter = 1
		} else {
			sampleCounter++
		}
	}
	wg.Wait()
}

func analyze(p *gopacket.Packet, ch *chan packetInfo) {
	var pInfo packetInfo
	pInfo.Time = (*p).Metadata().Timestamp.String()
	pInfo.Epochtime = (*p).Metadata().Timestamp.Unix()
	pInfo.Length = (*p).Metadata().Length
	pInfo.SrcMac = (*p).LinkLayer().LinkFlow().Src().String()
	pInfo.DstMac = (*p).LinkLayer().LinkFlow().Dst().String()

	for _, layer := range (*p).Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			ip, _ := layer.(*layers.IPv4)
			if pInfo.SrcIP == "" {
				pInfo.SrcIP = ip.SrcIP.String()
				pInfo.DstIP = ip.DstIP.String()
				pInfo.Proto = ip.Protocol.String()
			}

		case layers.LayerTypeIPv6:
			ip, _ := layer.(*layers.IPv6)
			pInfo.Proto = ip.LayerType().String()
			if pInfo.SrcIP == "" {
				pInfo.SrcIP = ip.SrcIP.String()
				pInfo.DstIP = ip.DstIP.String()
			}

		case layers.LayerTypeICMPv4:
			icmpv4 := layer.(*layers.ICMPv4)
			pInfo.Proto = layer.LayerType().String()
			pInfo.IcmpCode = int(icmpv4.TypeCode.Code())
			pInfo.IcmpType = int(icmpv4.TypeCode.Type())

		case layers.LayerTypeICMPv6:
			icmpv4 := layer.(*layers.ICMPv6)
			pInfo.Proto = layer.LayerType().String()
			pInfo.IcmpCode = int(icmpv4.TypeCode.Code())
			pInfo.IcmpType = int(icmpv4.TypeCode.Type())

		case layers.LayerTypeTCP:
			tcp, _ := layer.(*layers.TCP)
			pInfo.SrcPort = int(tcp.SrcPort)
			pInfo.DstPort = int(tcp.DstPort)
			pInfo.Seq = tcp.Seq
			pInfo.TCPFlags.FIN = tcp.FIN
			pInfo.TCPFlags.SYN = tcp.SYN
			pInfo.TCPFlags.RST = tcp.RST
			pInfo.TCPFlags.PSH = tcp.PSH
			pInfo.TCPFlags.ACK = tcp.ACK
			pInfo.TCPFlags.URG = tcp.URG
			pInfo.TCPFlags.ECE = tcp.ECE
			pInfo.TCPFlags.CWR = tcp.CWR
			pInfo.TCPFlags.NS = tcp.NS
			pInfo.TCPFlags.calcBit()

		case layers.LayerTypeUDP:
			udp, _ := layer.(*layers.UDP)
			pInfo.SrcPort = int(udp.SrcPort)
			pInfo.DstPort = int(udp.DstPort)

		default:
			if pInfo.Proto == "" {
				pInfo.Proto = layer.LayerType().String()
			}
		}
	}
	*ch <- pInfo
}
