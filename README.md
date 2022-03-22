# go-haproxy

A simple library that allows you to add support
for [HAProxy protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) to your project. It allows you to
get real IP addresses of clients connected via HAProxy or forward IP addresses to other servers that support HAProxy
protocol. This library supports only Version 2 of protocol as most other apps that ever supported HAProxy.

## Installation

You can install `go-haproxy` using Go modules:

```shell
go get github.com/ruscalworld/go-haproxy
```

## A few words on protocol

HAProxy's protocol is quite simple. All that HAProxy does to forward client address to the target server is sends some
data after the connection is being established and before any other data is sent. This data forms a so-called _PROXY
protocol header_. It contains such information as used protocol, source and destination IP address and ports, etc.

## Using

You can use this library for both: parsing and serializing HAProxy headers.

### Serializing

Let's assume that you are building a TCP proxy server that should forward client address to a backend server. In this
case you should just initialize a new instance of `haproxy.Header` structure, fill it with data and send to your
backend server.

```go
package main

import (
	"fmt"
	"net"
	
	"github.com/ruscalworld/go-haproxy"
)

func main() {
	// You should obtain this data from client's connection
	clientAddress := &net.TCPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 55555,
	}
	
	serverAddress := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}
	
	// WrapAddress is a convenience function that makes a ProxyAddress that you
	// can use in Header struct
	address, _ := haproxy.WrapAddress(clientAddress, serverAddress)

	header := haproxy.Header{
		// In most cases you should use PROXY command which tells the target server
		// that your header contains a client address, and you are going to forward
		// the entire connection
		Command: haproxy.CommandPROXY,
		
		// Address data that should be forwarded to the backend server, includes
		// source and destination address
		ProxyAddress: address,
	}

	// Connect to your backend
	conn, _ := net.Dial("tcp", serverAddress.String())
	
	// And write the PROXY protocol header
	header.WriteTo(conn)
	
	// Then handle connection as you wish
}
```
