# Gonsan

Gonsan is pcap analyzer to output json. 

## Getting Started

### Build

Build on Ubuntu

```
make first-build
```

### Run

1. Run `./gonsan -r read-awsome.pcap`
1. You can see json

json example

```json
{"time":"2017-11-11 16:28:34.966029 +0900 JST","epoch_time":1510385314,"length":248,"src_mac":"00:15:5d:00:07:00","dst_mac":"00:15:5d:00:07:01","src_ip":"192.168.0.1","dst_ip":"192.168.0.2","src_port":42086,"dst_port":443,"proto":"TCP","seq_num":1709215608,"tcp_flags":{"FIN":false,"SYN":false,"RST":false,"PSH":true,"ACK":true,"URG":false,"ECE":false,"CWR":false,"NS":false}}
```

## Configuration

### Argument

- **-r**
  - set pcap file name
- **-i**
  - set network interface name
- **-s**
  - sampling rate
  - `gonsan -s 100` -> sampling 1/100
  - default 1

require set `-r` or `-i` .  

## Json

- time
  - *string*
  - example - `"2017-11-09 00:35:09.32589 +0900 JST"`
- epoch_time
  - *int*
- length
  - *int*
- src_mac
  - *string*
- dst_mac
  - *string*
- src_ip
  - *string*
- dst_ip
  - *string*
- src_port
  - *int*
- dst_port:
  - *int*
- proto
  - *string*
- tcp_flags
  - FIN
    - *bool*
  - SYN
    - *bool*
  - RST
    - *bool*
  - PSH
    - *bool*
  - ACK
    - *bool*
  - URG
    - *bool*
  - ECE
    - *bool*
  - CWR
    - *bool*
  - NS
    - *bool*

## What's purpose for?

The goal is to sample a large pcap file and analyze it for IP addresses, ports and TCP flags.  
The sampling is a simple round robin, so it does not sample flow by flow.  
It is assumed to be used when TCP flow is not important (such as DDoS attack, SYN-Flood).

## What you really needs

- NetFlow
- sFlow
- packetbeat

## License

MIT
