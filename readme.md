# Gonsan

Gonsan is packet analyzer to output json. 

## Getting Started

1. Install [libpfring](https://github.com/ntop/PF_RING)
1. Run `sudo ./gonsan -i eth0` (read eth0 interface)
1. You can see json

json example

```json
{"time":"2017-11-09 00:35:09.32589 +0900 JST","epoch_time":1510155309,"length":179,"src_mac":"f8:63:3f:17:0b:7e","dst_mac":"f8:63:3f:7f:ff:fa","src_ip":"192.168.0.1","dst_ip":"192.168.0.2","src_port":52361,"dst_port":1900,"proto":"UDP","tcp_flags":0}
```

## Build

install pfring(libpfring)

```sh
go build gonsan.go
```

## Configuration

#### Argument

- **-i**
  - interface
- **-f**
  - BPF filter
  - optional
- **-s**
  - sampling rate
  - optional
  - `gonsan -s 100` -> sampling 1/100
  - default 1

## Json

- time"
  - string
  - example - `"2017-11-09 00:35:09.32589 +0900 JST"`
- epoch_time
  - int
- length
  - int
- src_mac
  - string
- dst_mac
  - string
- src_ip
  - string
- dst_ip
  - string
- src_port
  - int
- dst_port:
  - int
- proto
  - string
- tcp_flags
  - *not impremented*

## Feature

- view TCP flags
- select Aggregate

## What you really needs

- NetFlow
- sFlow
- packetbeat

## License

MIT
