package main

import (
	"flag"
	"fmt"

	"./analyze"
)

func main() {
	pcapFile := flag.String("r", "", "pcap file name")
	ifname := flag.String("i", "", "network interface name")
	samplingRate := flag.Int("s", 1, "sampling rate")
	flag.Parse()

	if *pcapFile != "" {
		analyze.ReadPcap(pcapFile, samplingRate)
	} else if (*ifname != "") {
		analyze.ReadIF(ifname, samplingRate)
	} else {
		fmt.Println("set read pcap or read interface")
		flag.PrintDefaults()
	}
}
