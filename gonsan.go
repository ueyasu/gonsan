package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"encoding/json"

	"gopkg.in/yaml.v2"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
)

type config struct {
	Input  inputConfig  `yaml:"input"`
	Filter filterConfig `yaml:"filter"`
	Output outputConfig `yaml:"output"`
}

type inputConfig struct {
	Device string `yaml:"device"`
}

type filterConfig struct {
	BpfFilter    string `yaml:"bpf_filter"`
	SamplingRate int    `yaml:"sampling_rate"`
}

type outputConfig struct {
}

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
	Seq       uint32   `json:"seq_num"`
	TCPFlags  tcpFlags `json:"tcp_flags, ,omitempty"`
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
			fallthrough
		case layers.LayerTypeIPv6:
			ip, _ := layer.(*layers.IPv4)
			if pInfo.SrcIP == "" {
				pInfo.SrcIP = ip.SrcIP.String()
				pInfo.DstIP = ip.DstIP.String()
				pInfo.Proto = ip.Protocol.String()
			}
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
		case layers.LayerTypeUDP:
			udp, _ := layer.(*layers.UDP)
			pInfo.SrcPort = int(udp.SrcPort)
			pInfo.DstPort = int(udp.DstPort)
		}
	}
	*ch <- pInfo
}

func view(p packetInfo) {
	fmt.Println(p.String())
}

func openConfig(path *string) (config, error) {
	var c config
	buf, err := ioutil.ReadFile(*path)
	if err != nil {
		return c, err
	}
	err = yaml.Unmarshal(buf, &c)
	return c, err
}

func main() {
	configPath := flag.String("f", "", "config file")
	device := flag.String("i", "", "interface")
	samplingRate := flag.Int("s", 1, "sampling rate")
	flag.Parse()

	var (
		conf config
		err  error
	)
	if *configPath != "" {
		if conf, err = openConfig(configPath); err != nil {
			log.Fatal(err)
		}
	}
	if *device != "" {
		conf.Input.Device = *device
	}
	if conf.Filter.SamplingRate < *samplingRate {
		conf.Filter.SamplingRate = *samplingRate
	}
	if conf.Input.Device == "" {
		log.Fatal(errors.New("set interface"))
	}

	if ring, err := pfring.NewRing(conf.Input.Device, 65536, pfring.FlagPromisc); err != nil {
		log.Println("Infomarion: check Permission")
		log.Fatal(err)
	} else if err := ring.SetBPFFilter(conf.Filter.BpfFilter); err != nil {
		log.Fatal(err)
	} else if err := ring.SetSamplingRate(*samplingRate); err != nil {
		log.Fatal(err)
	} else if err := ring.Enable(); err != nil {
		log.Fatal(err)
	} else {
		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		ch := make(chan packetInfo)
		for packet := range packetSource.Packets() {
			go analyze(&packet, &ch)
			go view(<-ch)
		}
	}
}
