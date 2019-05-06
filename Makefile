GO=go
NAME=gonsan

first-build: apt-get get build

apt-get:
	apt install libpcap-dev

get:
	$(GO) get github.com/google/gopacket
	$(GO) get github.com/google/gopacket/layers

build:
    GO111MODULE=off
	$(GO) build -ldflags '-w -s' -o $(NAME) -v

