package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"

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
	Time      string `json:"time"`
	Epochtime int64  `json:"epoch_time"`
	Length    int    `json:"length"`
	SrcMac    string `json:"src_mac"`
	DstMac    string `json:"dst_mac"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	TcpFlags  int    `json:"tcp_flags"`
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
			if net := (*p).NetworkLayer(); net != nil {
				pInfo.SrcIP = net.NetworkFlow().Src().String()
				pInfo.DstIP = net.NetworkFlow().Dst().String()
			}
		case layers.LayerTypeTCP:
			fallthrough
		case layers.LayerTypeUDP:
			pInfo.Proto = layer.LayerType().String()
			pInfo.SrcPort, _ = strconv.Atoi((*p).TransportLayer().TransportFlow().Src().String())
			pInfo.DstPort, _ = strconv.Atoi((*p).TransportLayer().TransportFlow().Dst().String())
		default:
			if proto := layer.LayerType().String(); proto != "Payload" {
				pInfo.Proto = proto
			}
		}
	}
	*ch <- pInfo
}

// func calcTcpFlags(tcp ) int {
// 	var flags int
// 	return flags
// }

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
		conf.Input.Device = *device
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
