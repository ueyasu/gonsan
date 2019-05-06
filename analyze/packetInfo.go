package analyze

import (
	"encoding/json"
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

func (p *packetInfo) String() string {
	jsonBytes, err := json.Marshal(*p)
	if err != nil {
		return ""
	}
	return string(jsonBytes)
}
