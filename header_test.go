package haproxy

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var encodedHeaders = [][]byte{
	{ // Normal IPv4 TCP header
		0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c,
		0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xa5, 0xce, 0x05, 0x3a,
	},
	{ // Header with broken signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c,
		0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xa5, 0xce, 0x05, 0x3a,
	},
}

var decodeTests = []func(t *testing.T, header *Header, read int, err error){
	func(t *testing.T, header *Header, read int, err error) {
		assert.Equal(t, 28, read)
		assert.Equal(t, CommandPROXY, header.Command)
		assert.NotNil(t, header.ProxyAddress)

		addr := header.ProxyAddress.(*IPv4Address)
		assert.Equal(t, &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 42446}, addr.SourceAddr)
		assert.Equal(t, &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 1338}, addr.DestinationAddr)
	},
	func(t *testing.T, header *Header, read int, err error) {
		assert.Equal(t, 12, read)
		assert.NotNil(t, err)
		assert.IsType(t, &ProxyProtocolError{}, err)
	},
}

func TestHeader_ReadFrom(t *testing.T) {
	for i, data := range encodedHeaders {
		reader := bytes.NewReader(data)

		var header Header
		n, err := header.ReadFrom(reader)

		test := decodeTests[i]
		test(t, &header, int(n), err)
	}
}

var headers = []*Header{
	{
		Command: CommandPROXY,
		ProxyAddress: &IPv4Address{
			SourceAddr:      &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 42446},
			DestinationAddr: &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 1338},
		},
	},
}

var expectedEncodedHeaders = [][]byte{
	{
		0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c,
		0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xa5, 0xce, 0x05, 0x3a,
	},
}

func TestHeader_WriteTo(t *testing.T) {
	for i, header := range headers {
		buffer := &bytes.Buffer{}
		n, err := header.WriteTo(buffer)

		expected := expectedEncodedHeaders[i]
		assert.Nil(t, err)
		assert.Equal(t, len(expected), int(n))
		assert.Equal(t, expected, buffer.Bytes())
	}
}
