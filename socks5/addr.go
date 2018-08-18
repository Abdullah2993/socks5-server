package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

//ErrInvalidPort is returned if the port is invalid
var ErrInvalidPort = errors.New("socks5: invalid port number")

//ErrInvalidAddr is returned if the addr is invalid
var ErrInvalidAddr = errors.New("socks5: invalid address")

var nullIPv4SocksAddr = &socksAddr{Type: AddrTypeIPv4, Addr: "0.0.0.0:0"}

//AddrType is the Address type defined in SOCKS5
type AddrType byte

const (
	//AddrTypeIPv4 is an IPv4 address
	AddrTypeIPv4 AddrType = 0x01
	//AddrTypeDomain is a uint8 length prefixed domain address
	AddrTypeDomain AddrType = 0x03
	//AddrTypeIPv6 is an IPv6 address
	AddrTypeIPv6 AddrType = 0x04
)

var addrTypeString = map[AddrType]string{
	AddrTypeIPv4:   "ipv4",
	AddrTypeIPv6:   "ipv6",
	AddrTypeDomain: "domain",
}

type socksAddr struct {
	Type AddrType
	Addr string
}

var _ net.Addr = (*socksAddr)(nil)

func (s *socksAddr) Network() string {
	return addrTypeString[s.Type]
}

func (s *socksAddr) String() string {
	return s.Addr
}

func (s *socksAddr) Marshal(b []byte) (int, error) {

	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		log.Printf("socks5:addr invalid address: %v", err)
		return 0, ErrInvalidAddr
	}

	ip := net.ParseIP(host)
	if ip == nil && (s.Type == AddrTypeIPv4 || s.Type == AddrTypeIPv6) {
		return 0, ErrInvalidAddr
	}

	al := 0
	switch s.Type {
	case AddrTypeIPv4:
		al = net.IPv4len
	case AddrTypeIPv6:
		al = net.IPv6len
	case AddrTypeDomain:
		al = 1 + len(host)
	}

	if b == nil || len(b) < al+3 {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(s.Type)

	switch s.Type {
	case AddrTypeIPv4:
		copy(b[1:], ip.To4())
	case AddrTypeIPv6:
		copy(b[1:], ip.To16())
	case AddrTypeDomain:
		b[1] = byte(len(host))
		copy(b[2:], host)
	}

	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		log.Printf("socks5:addr unable to parse port: %v", err)
		return 0, ErrInvalidPort
	}

	binary.BigEndian.PutUint16(b[1+al:], uint16(p))
	return 3 + al, nil
}

func newAddr(addr string) *socksAddr {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("socks5:addr invalid address: %v", err)
		return nil
	}

	s := &socksAddr{Addr: addr, Type: AddrTypeDomain}

	ip := net.ParseIP(host)
	if ip == nil {
		return s
	}

	if ip.To4() != nil {
		s.Type = AddrTypeIPv4
		return s
	}
	s.Type = AddrTypeIPv6
	return s
}
