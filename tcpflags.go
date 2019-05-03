package main

import "github.com/google/gopacket/layers"

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

func (f *tcpFlags) setFlags(tcp *layers.TCP) {
	f.FIN = tcp.FIN
	f.SYN = tcp.SYN
	f.RST = tcp.RST
	f.PSH = tcp.PSH
	f.ACK = tcp.ACK
	f.URG = tcp.URG
	f.ECE = tcp.ECE
	f.CWR = tcp.CWR
	f.NS = tcp.NS
	f.calcBit()
}

func (f *tcpFlags) calcBit() {
	f.BIT = 0
	if f.FIN == true {
		f.BIT = f.BIT | 1
	}
	if f.SYN == true {
		f.BIT = f.BIT | 2
	}
	if f.RST == true {
		f.BIT = f.BIT | 4
	}
	if f.PSH == true {
		f.BIT = f.BIT | 8
	}
	if f.ACK == true {
		f.BIT = f.BIT | 16
	}
	if f.URG == true {
		f.BIT = f.BIT | 32
	}
	if f.ECE == true {
		f.BIT = f.BIT | 64
	}
	if f.CWR == true {
		f.BIT = f.BIT | 128
	}
	if f.NS == true {
		f.BIT = f.BIT | 256
	}
}
