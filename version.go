package haproxy

import (
	"io"
)

const ProtocolVersion byte = 0x2

type Command byte

const (
	CommandLOCAL Command = iota
	CommandPROXY
)

type VersionByte struct {
	ProtocolVersion byte
	Command         Command
}

func (v *VersionByte) ReadFrom(r io.Reader) (n int64, err error) {
	data := make([]byte, 1)
	m, err := r.Read(data)
	n += int64(m)
	if err != nil {
		return n, err
	}

	v.ProtocolVersion = data[0] >> 4
	v.Command = Command(data[0] & 0b1111)
	return
}

func (v VersionByte) WriteTo(w io.Writer) (n int64, err error) {
	m, err := w.Write([]byte{v.ProtocolVersion<<4 | byte(v.Command)})
	return int64(m), err
}
