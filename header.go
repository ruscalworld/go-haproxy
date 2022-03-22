package haproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

var ProtocolSignature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

type Header struct {
	Command      Command
	ProxyAddress ProxyAddress
}

type ProxyProtocolError struct {
	Expected []byte
	Found    []byte
}

func (p ProxyProtocolError) Error() string {
	return "unexpected bytes in the beginning of header, there was no protocol header present"
}

type TransportProtocolError struct {
	TransportProtocol TransportProtocol
	AddressFamily     AddressFamily
	AddressLength     AddressLength
}

func (p TransportProtocolError) Error() string {
	return fmt.Sprintf(
		"unsupported protocol %x with address type %x (length %d)",
		p.TransportProtocol, p.AddressFamily, p.AddressLength,
	)
}

func (h *Header) ReadFrom(r io.Reader) (m int64, err error) {
	signature := make([]byte, 12)
	n, err := r.Read(signature)
	m += int64(n)
	if err != nil {
		return m, err
	}

	if !bytes.Equal(signature, ProtocolSignature) {
		return m, &ProxyProtocolError{ProtocolSignature, signature}
	}

	// Read protocol version and command, combined in a single byte
	var version VersionByte
	k, err := version.ReadFrom(r)
	m += k
	if err != nil {
		return m, err
	}

	// As of this specification, it must always be sent as \x2 and the receiver must only accept this value.
	if version.ProtocolVersion != ProtocolVersion {
		return m, fmt.Errorf("unsupported protocol version: expected %x, but got %x", ProtocolVersion, version.ProtocolVersion)
	}

	// Other values are unassigned and must not be emitted by senders. Receivers
	// must drop connections presenting unexpected values here.
	if version.Command != CommandLOCAL && version.Command != CommandPROXY {
		return m, fmt.Errorf("unsupported command: expected either 0x0 or 0x1, but got %x", version.Command)
	}

	h.Command = version.Command

	var protocol ProtocolByte
	k, err = protocol.ReadFrom(r)
	m += k
	if err != nil {
		return
	}

	// Other values are unspecified and must not be emitted in version 2 of the
	// protocol and must be rejected as invalid by receivers.
	if protocol.AddressFamily != AddressFamilyUNSPEC && protocol.AddressFamily != AddressFamilyINET &&
		protocol.AddressFamily != AddressFamilyINET6 && protocol.AddressFamily != AddressFamilyUNIX {
		return m, fmt.Errorf("unsupported address family: expected 0x0 - 0x3, but got %x", protocol.AddressFamily)
	}

	// Other values are unspecified and must not be emitted in version 2 of the
	// protocol and must be rejected as invalid by receivers.
	if protocol.TransportProtocol != TransportProtocolUNSPEC && protocol.TransportProtocol != TransportProtocolSTREAM &&
		protocol.TransportProtocol != TransportProtocolDGRAM {
		return m, fmt.Errorf("unsupported transport protocol: expected 0x0 - 0x2, but got %x", protocol.TransportProtocol)
	}

	var addressLength AddressLength
	k, err = addressLength.ReadFrom(r)
	m += k
	if err != nil {
		return
	}

	// If there is no address data (e.g. in cases when command is LOCAL),
	// let's just finish reading and return
	if addressLength == 0 {
		return
	}

	switch protocol {
	// TCP over IPv4
	case ProtocolByte{AddressFamilyINET, TransportProtocolSTREAM}:
		result, n, err := readIPsAndPorts(r, 4)
		m += int64(n)
		if err != nil {
			return m, err
		}

		h.ProxyAddress = &IPv4Address{
			SourceAddr: &net.TCPAddr{
				IP:   *result.sourceIP,
				Port: int(result.sourcePort),
			},
			DestinationAddr: &net.TCPAddr{
				IP:   *result.destinationIP,
				Port: int(result.destinationPort),
			},
		}
	// UDP over IPv4
	case ProtocolByte{AddressFamilyINET, TransportProtocolDGRAM}:
		result, n, err := readIPsAndPorts(r, 4)
		m += int64(n)
		if err != nil {
			return m, err
		}

		h.ProxyAddress = &IPv4Address{
			SourceAddr: &net.UDPAddr{
				IP:   *result.sourceIP,
				Port: int(result.sourcePort),
			},
			DestinationAddr: &net.UDPAddr{
				IP:   *result.destinationIP,
				Port: int(result.destinationPort),
			},
		}
	// TCP over IPv6
	case ProtocolByte{AddressFamilyINET6, TransportProtocolSTREAM}:
		result, n, err := readIPsAndPorts(r, 16)
		m += int64(n)
		if err != nil {
			return m, err
		}

		h.ProxyAddress = &IPv6Address{
			SourceAddr: &net.TCPAddr{
				IP:   *result.sourceIP,
				Port: int(result.sourcePort),
			},
			DestinationAddr: &net.TCPAddr{
				IP:   *result.destinationIP,
				Port: int(result.destinationPort),
			},
		}
	// UDP over IPv6
	case ProtocolByte{AddressFamilyINET6, TransportProtocolDGRAM}:
		result, n, err := readIPsAndPorts(r, 16)
		m += int64(n)
		if err != nil {
			return m, err
		}

		h.ProxyAddress = &IPv6Address{
			SourceAddr: &net.UDPAddr{
				IP:   *result.sourceIP,
				Port: int(result.sourcePort),
			},
			DestinationAddr: &net.UDPAddr{
				IP:   *result.destinationIP,
				Port: int(result.destinationPort),
			},
		}
	// UNIX stream
	case ProtocolByte{AddressFamilyUNIX, TransportProtocolSTREAM}:
		result, n, err := readUnix(r)
		m += int64(n)
		if err != nil {
			return m, err
		}

		h.ProxyAddress = &UnixAddr{
			SourceAddr: &net.UnixAddr{
				Name: string(result.SourceAddr),
				Net:  "unixpacket",
			},
			DestinationAddr: &net.UnixAddr{
				Name: string(result.DestinationAddr),
				Net:  "unixpacket",
			},
		}
	// UNIX datagram
	case ProtocolByte{AddressFamilyUNIX, TransportProtocolDGRAM}:
		result, n, err := readUnix(r)
		m += int64(n)
		if err != nil {
			return m, err
		}

		h.ProxyAddress = &UnixAddr{
			SourceAddr: &net.UnixAddr{
				Name: string(result.SourceAddr),
				Net:  "unixgram",
			},
			DestinationAddr: &net.UnixAddr{
				Name: string(result.DestinationAddr),
				Net:  "unixgram",
			},
		}
	// If protocol is not supported, read remaining bytes and return an error
	default:
		data := make([]byte, addressLength)
		n, err := r.Read(data)
		m += int64(n)
		if err != nil {
			return m, err
		}

		return m, &TransportProtocolError{protocol.TransportProtocol, protocol.AddressFamily, addressLength}
	}

	return
}

func (h Header) WriteTo(w io.Writer) (m int64, err error) {
	n, err := w.Write(ProtocolSignature)
	m += int64(n)
	if err != nil {
		return m, err
	}

	version := VersionByte{
		ProtocolVersion: ProtocolVersion,
		Command:         h.Command,
	}

	k, err := version.WriteTo(w)
	m += k
	if err != nil {
		return m, err
	}

	k, err = h.ProxyAddress.getSignature().WriteTo(w)
	m += k
	if err != nil {
		return
	}

	// We should write address data only if command is PROXY.
	// In case if command is LOCAL, address length is written as zero, and no address follows it
	if h.Command == CommandPROXY {
		k, err = h.ProxyAddress.getLength().WriteTo(w)
		m += k
		if err != nil {
			return
		}

		k, err = h.ProxyAddress.WriteTo(w)
		m += k
		if err != nil {
			return m, err
		}
	} else {
		k, err = AddressLength(0).WriteTo(w)
		m += k
		if err != nil {
			return
		}
	}

	return
}
