package main

import (
	"errors"
	"flag"
	"log"

	"./analyze"
)

func main() {
	pcapFile := flag.String("r", "", "read pcap")
	ifname := flag.String("i", "", "read network interface name")
	samplingRate := flag.Int("s", 1, "sampling rate")
	flag.Parse()

	if *pcapFile != "" {
		analyze.ReadPcap(pcapFile, samplingRate)
	} else if (*ifname != "") {
		analyze.ReadIF(ifname, samplingRate)
	} else {
		log.Fatal(errors.New("set read pcap or read interface"))
	}
}
