package socks5

import (
	"errors"
	"io"
	"net"
)

//AuthMethod defines the authentication method
type AuthMethod byte

const (
	noAuth       AuthMethod = 0x00
	userPassAuth AuthMethod = 0x02
	noAcceptable AuthMethod = 0xFF
)

//ErrAuthFailed is returned if authentication if failed
var ErrAuthFailed = errors.New("socks5: authentication failed")

//ErrInvalidSubNegotitationVer is returned if the version of the authentication method in use is not supported
var ErrInvalidSubNegotitationVer = errors.New("socks5: invalid subnegotitaion version")

//Authenticator is implemented by the authentication methods
type Authenticator interface {
	Authenticate(c net.Conn) error
	AuthMethod() AuthMethod
}

type nopeAuth struct{}

var _ Authenticator = (*nopeAuth)(nil)
var _ Authenticator = (*usernamePasswordAuth)(nil)

func (r nopeAuth) Authenticate(c net.Conn) error { return nil }

func (r nopeAuth) AuthMethod() AuthMethod { return noAuth }

//NoAuth is the no authentication AuhtMethod
var NoAuth = new(nopeAuth)

type usernamePasswordAuth struct {
	Username, Password string
}

func (r usernamePasswordAuth) AuthMethod() AuthMethod { return userPassAuth }

func (r usernamePasswordAuth) Authenticate(cn net.Conn) (err error) {
	c, _ := cn.(*conn)

	if _, err = io.ReadFull(c, c.buf[0:2]); err != nil {
		return
	}
	if c.buf[0] != subNegotiationVer {
		err = ErrInvalidSubNegotitationVer
		return
	}

	ul := int(c.buf[1])
	if _, err = io.ReadFull(c, c.buf[:ul+1]); err != nil {
		return
	}
	user := string(c.buf[:ul])

	pl := int(c.buf[ul])
	if _, err = io.ReadFull(c, c.buf[:pl]); err != nil {
		return
	}
	pass := string(c.buf[:pl])

	c.buf[0] = subNegotiationVer
	c.buf[1] = 0x00
	if user != r.Username || pass != r.Password {
		c.buf[1] = 0xED
		err = ErrAuthFailed
	}

	if _, err := c.Write(c.buf[:2]); err != nil {
		return err
	}
	return
}

//NewUserPassAuth creates a new username/password based authenticator
func NewUserPassAuth(username, password string) Authenticator {
	return &usernamePasswordAuth{Username: username, Password: password}
}
