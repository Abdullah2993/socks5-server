package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	socksVer5         byte = 0x05
	reserve           byte = 0x00
	subNegotiationVer byte = 0x01
)

//Command is the Commands Defined by SOCKS5 RFC1928
type Command byte

const (
	//CommandConnect CONNECT command
	CommandConnect Command = 0x01
	//CommandBind BIND command
	CommandBind Command = 0x02
	//CommandUDPAssociation UDP Association command
	CommandUDPAssociation Command = 0x03
)

type responseType byte

const (
	responseSuccess             responseType = 0x00
	responseGeneralFailure      responseType = 0x01
	responseNotAllowedByRuleset responseType = 0x02
	responseNetworkUnreachable  responseType = 0x03
	responseHostUnreachable     responseType = 0x04
	responseConnectionRefused   responseType = 0x05
	responseTTLExpired          responseType = 0x06
	responseCommandNotSupported responseType = 0x07
	responseAddressNotSupported responseType = 0x08
)

//ErrInvalidSocksVer is returned if the SOCKS version in not 5
var ErrInvalidSocksVer = errors.New("socks5: invalid socks version")

//ErrNoAcceptableMethod is returend if clients doesn't offer an acceptable authentication method
var ErrNoAcceptableMethod = errors.New("socks4: no accaptable method")

//ErrAddressTypeNotSupported is returned if the AddrType is not supported by the server
var ErrAddressTypeNotSupported = errors.New("socks5: address type not supported")

type conn struct {
	net.Conn
	buf []byte
}

func newConn(c net.Conn) *conn {
	return &conn{
		Conn: c,
		buf:  make([]byte, 520),
	}
}

func (c *conn) Negoatiate(auth AuthMethod) error {
	accept := byte(noAcceptable)
	if _, err := io.ReadFull(c, c.buf[:2]); err != nil {
		return err
	}

	if c.buf[0] != socksVer5 {
		return ErrInvalidSocksVer
	}
	methodCount := c.buf[1]

	if _, err := io.ReadFull(c, c.buf[:methodCount]); err != nil {
		return err
	}

	if i := bytes.IndexByte(c.buf[:methodCount], byte(auth)); i != -1 {
		accept = c.buf[i]
	}

	c.buf[0] = socksVer5
	c.buf[1] = accept
	if _, err := c.Write(c.buf[:2]); err != nil {
		return err
	}

	if accept == byte(noAcceptable) {
		return ErrNoAcceptableMethod
	}
	return nil
}

func (c *conn) ReadCommandRequest() (method Command, addr *socksAddr, err error) {

	if _, err = io.ReadFull(c, c.buf[:5]); err != nil {
		return
	}

	if c.buf[0] != socksVer5 { //shouldn't happen. but in case disconnect immediately
		err = ErrInvalidSocksVer
		return
	}

	method = Command(c.buf[1])

	addrLength := 0
	domain := false
	offset := 1
	addrType := AddrType(c.buf[3])
	switch addrType { //buf[2] is reserve
	case AddrTypeIPv4:
		addrLength = net.IPv4len
	case AddrTypeIPv6:
		addrLength = net.IPv6len
	case AddrTypeDomain:
		addrLength = int(c.buf[4])
		domain = true
		offset = 0
	default:
		err = ErrAddressTypeNotSupported
		return
	}

	c.buf[0] = c.buf[4]

	if _, err = io.ReadFull(c, c.buf[offset:addrLength+2]); err != nil {
		return
	}

	addrBytes := c.buf[:addrLength]

	port := int(binary.BigEndian.Uint16(c.buf[addrLength : addrLength+2]))

	targetHost := string(addrBytes)

	if !domain {
		ip := net.IP(addrBytes)
		targetHost = ip.String()
	}

	addr = &socksAddr{Type: addrType, Addr: net.JoinHostPort(targetHost, strconv.Itoa(port))}
	return
}

func (c *conn) WriteCommandResponse(res responseType, addr string) error {
	c.buf[0] = socksVer5
	c.buf[1] = byte(res)
	c.buf[2] = reserve

	saddr := newAddr(addr)
	if saddr == nil {
		return ErrInvalidAddr
	}

	addrLen, err := saddr.Marshal(c.buf[3:])
	if err != nil {
		return err
	}
	_, err = c.Write(c.buf[:3+addrLen])
	return err
}

func (c *conn) WriteError(res responseType) error {
	errRes := []byte{socksVer5, 0x01, reserve, byte(AddrTypeIPv4), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	copy(errRes, c.buf) //why? why not?
	c.buf[1] = byte(res)
	_, err := c.Write(c.buf[:10])
	return err
}

// Relay should fail silently and just return
func (c *conn) Relay(tconn net.Conn) {
	go func() {
		defer tconn.Close()
		io.Copy(c, tconn)
	}()
	io.Copy(tconn, c)
}
