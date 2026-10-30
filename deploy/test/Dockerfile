FROM golang:1.26 AS go
FROM ubuntu:26.04
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" GOPATH=/go
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates nftables iputils-ping tshark tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN go mod download
ENV VIGILANTE_LINUX_INTEGRATION=1
CMD ["go","test","-v","./pkg/tap","-run","TestLinux"]
