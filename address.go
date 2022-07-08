package haproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
)

type AddressFamily byte

const (
	// AddressFamilyUNSPEC the connection is forwarded for an unknown, unspecified
	// or unsupported protocol. The sender should use this family when sending
	// LOCAL commands or when dealing with unsupported protocol families. The
	// receiver is free to accept the connection anyway and use the real endpoint
	// addresses or to reject it. The receiver should ignore address information.
	AddressFamilyUNSPEC AddressFamily = iota

	// AddressFamilyINET the forwarded connection uses the AF_INET address family
	// (IPv4). The addresses are exactly 4 bytes each in network byte order,
	// followed by transport protocol information (typically ports).
	AddressFamilyINET

	// AddressFamilyINET6 the forwarded connection uses the AF_INET6 address family
	// (IPv6). The addresses are exactly 16 bytes each in network byte order,
	// followed by transport protocol information (typically ports).
	AddressFamilyINET6

	// AddressFamilyUNIX the forwarded connection uses the AF_UNIX address family
	// (UNIX). The addresses are exactly 108 bytes each.
	AddressFamilyUNIX
)

type TransportProtocol byte

const (
	// TransportProtocolUNSPEC the connection is forwarded for an unknown, unspecified
	// or unsupported protocol. The sender should use this family when sending
	// LOCAL commands or when dealing with unsupported protocol families. The
	// receiver is free to accept the connection anyway and use the real endpoint
	// addresses or to reject it. The receiver should ignore address information.
	TransportProtocolUNSPEC TransportProtocol = iota

	// TransportProtocolSTREAM the forwarded connection uses a SOCK_STREAM protocol (eg:
	// TCP or UNIX_STREAM). When used with AF_INET/AF_INET6 (TCP), the addresses
	// are followed by the source and destination ports represented on 2 bytes
	// each in network byte order.
	TransportProtocolSTREAM

	// TransportProtocolDGRAM the forwarded connection uses a SOCK_DGRAM protocol (eg:
	// UDP or UNIX_DGRAM). When used with AF_INET/AF_INET6 (UDP), the addresses
	// are followed by the source and destination ports represented on 2 bytes
	// each in network byte order.
	TransportProtocolDGRAM
)

type ProtocolByte struct {
	AddressFamily     AddressFamily
	TransportProtocol TransportProtocol
}

func (p *ProtocolByte) ReadFrom(r io.Reader) (n int64, err error) {
	data := make([]byte, 1)
	m, err := r.Read(data)
	n += int64(m)
	if err != nil {
		return n, err
	}

	p.AddressFamily = AddressFamily(data[0] >> 4)
	p.TransportProtocol = TransportProtocol(data[0] & 0b1111)
	return
}

func (p ProtocolByte) WriteTo(w io.Writer) (n int64, err error) {
	m, err := w.Write([]byte{byte(p.AddressFamily<<4) | byte(p.TransportProtocol)})
	return int64(m), err
}

type AddressLength int16

func (a *AddressLength) ReadFrom(r io.Reader) (n int64, err error) {
	data := make([]byte, 2)
	m, err := r.Read(data)
	n += int64(m)
	if err != nil {
		return n, err
	}

	length := AddressLength(binary.BigEndian.Uint16(data))
	*a = length
	return
}

func (a AddressLength) WriteTo(w io.Writer) (n int64, err error) {
	err = binary.Write(w, binary.BigEndian, a)
	if err != nil {
		return 0, err
	}

	return 2, nil // Since we have written address length which should be exactly 2 bytes long
}

func getTransportProtocol(addr net.Addr) TransportProtocol {
	switch addr.(type) {
	case *net.TCPAddr:
		return TransportProtocolSTREAM
	case *net.UDPAddr:
		return TransportProtocolDGRAM
	case *net.UnixAddr:
		if addr.Network() == "unixgram" {
			return TransportProtocolDGRAM
		}

		return TransportProtocolSTREAM
	default:
		panic("address type is not supported")
	}
}

func WrapAddress(src, dst net.Addr) (ProxyAddress, error) {
	if reflect.TypeOf(src) != reflect.TypeOf(dst) {
		return nil, fmt.Errorf(
			"expected source and destination addresses to be of the same type, but got source %s and destination %s",
			reflect.TypeOf(src).String(), reflect.TypeOf(dst).String(),
		)
	}

	if src == nil || dst == nil {
		return nil, fmt.Errorf("expected all addresses to present, got source %s and destination %s", src, dst)
	}

	switch src.(type) {
	case *net.TCPAddr, *net.UDPAddr:
		if strings.Count(src.String(), ":") > 1 {
			// Address is IPv6
			return &IPv6Address{
				SourceAddr:      src,
				DestinationAddr: dst,
			}, nil
		} else if strings.Count(src.String(), ".") == 3 {
			// Address is IPv4
			return &IPv4Address{
				SourceAddr:      src,
				DestinationAddr: dst,
			}, nil
		}
	case *net.UnixAddr:
		// Address is Unix
		return &UnixAddr{
			SourceAddr:      src.(*net.UnixAddr),
			DestinationAddr: dst.(*net.UnixAddr),
		}, nil
	}

	return nil, fmt.Errorf("address %s (%s) is not supported", src.String(), reflect.TypeOf(src).String())
}

func readPort(r io.Reader) (uint16, int, error) {
	port := make([]byte, 2)
	n, err := r.Read(port)
	if err != nil {
		return 0, n, err
	}

	return binary.BigEndian.Uint16(port), n, nil
}

func readIP(r io.Reader, length int) (*net.IP, int, error) {
	ip := make([]byte, length)
	n, err := r.Read(ip)
	if err != nil {
		return nil, n, err
	}

	return (*net.IP)(&ip), n, nil
}

type ipReadResult struct {
	sourceIP        *net.IP
	destinationIP   *net.IP
	sourcePort      uint16
	destinationPort uint16
}

func readIPsAndPorts(r io.Reader, addressLength int) (*ipReadResult, int, error) {
	m, n := 0, 0
	var err error
	result := &ipReadResult{}

	result.sourceIP, n, err = readIP(r, addressLength)
	m += n
	if err != nil {
		return nil, m, err
	}

	result.destinationIP, n, err = readIP(r, addressLength)
	m += n
	if err != nil {
		return nil, m, err
	}

	result.sourcePort, n, err = readPort(r)
	m += n
	if err != nil {
		return nil, m, err
	}

	result.destinationPort, n, err = readPort(r)
	m += n
	if err != nil {
		return nil, m, err
	}

	return result, m, nil
}

type unixReadResult struct {
	SourceAddr      []byte
	DestinationAddr []byte
}

func readUnix(r io.Reader) (*unixReadResult, int, error) {
	result := &unixReadResult{
		SourceAddr:      make([]byte, 108),
		DestinationAddr: make([]byte, 108),
	}

	n, err := r.Read(result.SourceAddr)
	if err != nil {
		return nil, n, err
	}

	m, err := r.Read(result.DestinationAddr)
	n += m
	if err != nil {
		return nil, n, err
	}

	return result, n, nil
}

func writePorts(w io.Writer, src, dst net.Addr) (m int64, err error) {
	err = binary.Write(w, binary.BigEndian, getPort(src))
	if err != nil {
		return m, err
	}
	m += 2 // Source port length

	err = binary.Write(w, binary.BigEndian, getPort(dst))
	if err != nil {
		return m, err
	}
	m += 2 // Destination port length

	return
}

func addressToBytes(addr net.Addr) []byte {
	switch addr.(type) {
	case *net.TCPAddr:
		return alignIP(addr.(*net.TCPAddr).IP)
	case *net.UDPAddr:
		return alignIP(addr.(*net.UDPAddr).IP)
	case *net.UnixAddr:
		data := make([]byte, 108)
		copy(data, addr.String())
		return data
	default:
		panic("address type is not supported")
	}
}

func alignIP(ip net.IP) []byte {
	if len(ip) < 16 {
		return append(make([]byte, 16-len(ip)), ip...)
	}

	return ip
}

func getPort(addr net.Addr) uint16 {
	switch addr.(type) {
	case *net.TCPAddr:
		return uint16(addr.(*net.TCPAddr).Port)
	case *net.UDPAddr:
		return uint16(addr.(*net.UDPAddr).Port)
	default:
		panic("address type is not supported")
	}
}

type ProxyAddress interface {
	io.WriterTo
	getLength() AddressLength
	getSignature() ProtocolByte
}

type IPv4Address struct {
	SourceAddr      net.Addr
	DestinationAddr net.Addr
}

func (a IPv4Address) WriteTo(w io.Writer) (m int64, err error) {
	n, err := w.Write(addressToBytes(a.SourceAddr)[12:])
	m += int64(n)
	if err != nil {
		return m, err
	}

	n, err = w.Write(addressToBytes(a.DestinationAddr)[12:])
	m += int64(n)
	if err != nil {
		return m, err
	}

	k, err := writePorts(w, a.SourceAddr, a.DestinationAddr)
	m += k
	if err != nil {
		return m, err
	}

	return
}

func (a IPv4Address) getLength() AddressLength {
	return 12
}

func (a IPv4Address) getSignature() ProtocolByte {
	return ProtocolByte{AddressFamilyINET, getTransportProtocol(a.SourceAddr)}
}

type IPv6Address struct {
	SourceAddr      net.Addr
	DestinationAddr net.Addr
}

func (a IPv6Address) WriteTo(w io.Writer) (m int64, err error) {
	n, err := w.Write(addressToBytes(a.SourceAddr))
	m += int64(n)
	if err != nil {
		return m, err
	}

	n, err = w.Write(addressToBytes(a.DestinationAddr))
	m += int64(n)
	if err != nil {
		return m, err
	}

	k, err := writePorts(w, a.SourceAddr, a.DestinationAddr)
	m += k
	if err != nil {
		return m, err
	}

	return
}

func (a IPv6Address) getLength() AddressLength {
	return 36
}

func (a IPv6Address) getSignature() ProtocolByte {
	return ProtocolByte{AddressFamilyINET6, getTransportProtocol(a.SourceAddr)}
}

type UnixAddr struct {
	SourceAddr      *net.UnixAddr
	DestinationAddr *net.UnixAddr
}

func (a UnixAddr) WriteTo(w io.Writer) (m int64, err error) {
	n, err := w.Write(addressToBytes(a.SourceAddr))
	m += int64(n)
	if err != nil {
		return m, err
	}

	n, err = w.Write(addressToBytes(a.DestinationAddr))
	m += int64(n)
	if err != nil {
		return m, err
	}

	return
}

func (a UnixAddr) getLength() AddressLength {
	return 216
}

func (a UnixAddr) getSignature() ProtocolByte {
	return ProtocolByte{AddressFamilyUNIX, getTransportProtocol(a.SourceAddr)}
}
