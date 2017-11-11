# Gonsan

Gonsan is packet analyzer to output json. 

## Getting Started

### 1. Install libpfring

Install [libpfring](https://github.com/ntop/PF_RING)

### 2. Build

```sh
go get "github.com/google/gopacket"
go get "gopkg.in/yaml.v2"
go build gonsan.go
```

### 3. Run

1. Run `sudo ./gonsan -i eth0` (read eth0 interface)
1. You can see json

json example

```json
{"time":"2017-11-11 16:28:34.966029 +0900 JST","epoch_time":1510385314,"length":248,"src_mac":"00:15:5d:00:07:00","dst_mac":"00:15:5d:00:07:01","src_ip":"192.168.0.1","dst_ip":"192.168.0.2","src_port":42086,"dst_port":443,"proto":"TCP","seq_num":1709215608,"tcp_flags":{"FIN":false,"SYN":false,"RST":false,"PSH":true,"ACK":true,"URG":false,"ECE":false,"CWR":false,"NS":false}}
```

### View elastic stack on Docker example

1. install docker
2. install docker-compose
3. run docker

```sh
$ cd exapmle-docker-elastic
$ docker-compospe up -d
$ sudo gonsan -i eth0 -s 10 > logstash.txt
```

view kibana http://localhost:5601

## Configuration

### Argument

- **-i**
  - interface
- **-f**
  - config file path
- **-s**
  - sampling rate
  - `gonsan -s 100` -> sampling 1/100
  - default 1

### config file

argument (-i, -s) overrides config.

````yaml
input:
  # set read interface
  device: "eth0"
filter:
  # set BPF filter
  bpf_filter: ""
  # samling rate
  sampling_rate: 1
````

example

```sh
gonsan -f config.yml -i eth0 -s 10
```

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

## What you really needs

- NetFlow
- sFlow
- packetbeat

## License

MIT
