package haproxy

import (
	"io"
)

var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const ProtocolVersion byte = 0x2

type Command byte

const (
	CommandLOCAL Command = iota
	CommandPROXY
)

type AddressFamily byte

const (
	AddressFamilyUNSPEC AddressFamily = iota
	AddressFamilyINET
	AddressFamilyINET6
	AddressFamilyUNIX
)

type TransportProtocol byte

const (
	TransportProtocolUNSPEC TransportProtocol = iota
	TransportProtocolSTREAM
	TransportProtocolDGRAM
)

type Header struct {
	Command      Command
	ProxyAddress ProxyAddress
}

func (h Header) WriteTo(w io.Writer) (m int64, err error) {
	n, err := w.Write(signature)
	m += int64(n)
	if err != nil {
		return m, err
	}

	n, err = w.Write([]byte{ProtocolVersion<<4 | byte(h.Command)})
	m += int64(n)
	if err != nil {
		return m, err
	}

	k, err := h.ProxyAddress.WriteTo(w)
	m += k
	if err != nil {
		return m, err
	}

	return
}
