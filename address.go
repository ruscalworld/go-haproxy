package haproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
)

func getTransportProtocol(addr net.Addr) TransportProtocol {
	switch addr.(type) {
	case *net.TCPAddr:
		return TransportProtocolSTREAM
	case *net.UDPAddr:
		return TransportProtocolDGRAM
	case *net.UnixAddr:
		// Protocol specification also allows using DGRAM type here
		return TransportProtocolSTREAM
	default:
		panic("address type is not supported")
	}
}

func WrapAddress(src, dst net.Addr) (ProxyAddress, error) {
	if reflect.TypeOf(src) != reflect.TypeOf(dst) {
		return nil, fmt.Errorf(
			"expected source and destination addresses to be of the same type, but got source %s and destination %s",
			reflect.TypeOf(src).String(), reflect.TypeOf(dst),
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
		} else if strings.Count(src.String(), ":") == 3 {
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

func writeAddressHeader(writer io.Writer, address ProxyAddress) (m int64, err error) {
	n, err := writer.Write([]byte{address.getSignature()})
	m += int64(n)
	if err != nil {
		return m, err
	}

	err = binary.Write(writer, binary.LittleEndian, address.getLength())
	if err != nil {
		return m, err
	}

	m += 2 // Since we have written address length which should be 2 bytes long
	return
}

func writePorts(w io.Writer, src, dst net.Addr) (m int64, err error) {
	err = binary.Write(w, binary.LittleEndian, getPort(src))
	if err != nil {
		return m, err
	}
	m += 2 // Source port length

	err = binary.Write(w, binary.LittleEndian, getPort(dst))
	if err != nil {
		return m, err
	}
	m += 2 // Destination port length

	return
}

func addressToBytes(addr net.Addr) []byte {
	switch addr.(type) {
	case *net.TCPAddr:
		return addr.(*net.TCPAddr).IP
	case *net.UDPAddr:
		return addr.(*net.UDPAddr).IP
	case *net.UnixAddr:
		data := make([]byte, 108)
		copy(data, addr.String())
		return data
	default:
		panic("address type is not supported")
	}
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
	getLength() int16
	getSignature() byte
}

type IPv4Address struct {
	SourceAddr      net.Addr
	DestinationAddr net.Addr
}

func (a IPv4Address) WriteTo(w io.Writer) (m int64, err error) {
	m, err = writeAddressHeader(w, a)
	if err != nil {
		return m, err
	}

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

func (a IPv4Address) getLength() int16 {
	return 12
}

func (a IPv4Address) getSignature() byte {
	return byte(AddressFamilyINET)<<4 | byte(getTransportProtocol(a.SourceAddr))
}

type IPv6Address struct {
	SourceAddr      net.Addr
	DestinationAddr net.Addr
}

func (a IPv6Address) WriteTo(w io.Writer) (m int64, err error) {
	m, err = writeAddressHeader(w, a)
	if err != nil {
		return m, err
	}

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

func (a IPv6Address) getLength() int16 {
	return 36
}

func (a IPv6Address) getSignature() byte {
	return byte(AddressFamilyINET6)<<4 | byte(getTransportProtocol(a.SourceAddr))
}

type UnixAddr struct {
	SourceAddr      *net.UnixAddr
	DestinationAddr *net.UnixAddr
}

func (a UnixAddr) WriteTo(w io.Writer) (m int64, err error) {
	m, err = writeAddressHeader(w, a)
	if err != nil {
		return m, err
	}

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

func (a UnixAddr) getLength() int16 {
	return 216
}

func (a UnixAddr) getSignature() byte {
	return byte(AddressFamilyUNIX)<<4 | byte(getTransportProtocol(a.SourceAddr))
}
