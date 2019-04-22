package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"runtime"
	"sync"

	"encoding/json"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type packetInfo struct {
	Time      string   `json:"time"`
	Epochtime int64    `json:"epoch_time"`
	Length    int      `json:"length"`
	SrcMac    string   `json:"src_mac"`
	DstMac    string   `json:"dst_mac"`
	SrcIP     string   `json:"src_ip ,omitempty"`
	DstIP     string   `json:"dst_ip ,omitempty"`
	SrcPort   int      `json:"src_port ,omitempty"`
	DstPort   int      `json:"dst_port ,omitempty"`
	Proto     string   `json:"proto"`
	Seq       uint32   `json:"seq_num ,omitempt"`
	TCPFlags  tcpFlags `json:"tcp_flags, ,omitempty"`
	IcmpCode  int      `json:"icmp_code,omitempty"`
	IcmpType  int      `json:"icmp_type,omitempty"`
}

type tcpFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
	BIT uint32
}

func (f *tcpFlags) calcBit() {
	f.BIT = 0
	if f.FIN {
		f.BIT |= 1
	}
	if f.SYN {
		f.BIT |= 2
	}
	if f.RST {
		f.BIT |= 4
	}
	if f.PSH {
		f.BIT |= 8
	}
	if f.ACK {
		f.BIT |= 16
	}
	if f.URG {
		f.BIT |= 32
	}
	if f.ECE {
		f.BIT |= 64
	}
	if f.CWR {
		f.BIT |= 128
	}
	if f.NS {
		f.BIT |= 256
	}
}

func (p *packetInfo) String() string {
	jsonBytes, err := json.Marshal(*p)
	if err != nil {
		return ""
	}
	return string(jsonBytes)
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

func view(p packetInfo) {
	fmt.Println(p.String())
}

func main() {
	pcapFile := flag.String("r", "", "read pcap")
	samplingRate := flag.Int("s", 1, "sampling rate")
	flag.Parse()

	var (
		handle *pcap.Handle
		err    error
	)

	if *pcapFile == "" {
		log.Fatal(errors.New("set read pcap"))
	}

	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	cpus := runtime.NumCPU()
	ch := make(chan packetInfo, cpus)
	wg := &sync.WaitGroup{}
	sampleCounter := *samplingRate

	for packet := range packetSource.Packets() {
		if sampleCounter == *samplingRate {
			wg.Add(1)
			go func(packet gopacket.Packet, ch chan packetInfo) {
				defer wg.Done()
				analyze(&packet, &ch)
				view(<-ch)
			}(packet, ch)
			sampleCounter = 1
		} else {
			sampleCounter++
		}
	}
	wg.Wait()
}
