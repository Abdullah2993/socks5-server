package socks5

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

//ErrServerClosed is returned by ListenAndServe when the server is closed by calling Close
var ErrServerClosed = errors.New("socks5: Server closed")

// Option is a Server option
type Option func(*Server)

//WithAuth sets the authentication for Server
func WithAuth(username, password string) Option {
	return func(s *Server) {
		s.Auth = NewUserPassAuth(username, password)
	}
}

//WithKeepAlive sets tcp KeepAlives for inbound/outbound connections
func WithKeepAlive(interval time.Duration) Option {
	return func(s *Server) {
		s.KeepAlive = interval
	}
}

//WithCommands sets allowed commands for the serve
func WithCommands(cmds ...Command) Option {
	return func(s *Server) {
		s.Cmds = cmds
	}
}

//WithDialer sets the dailer used for connect command
func WithDialer(d *net.Dialer) Option {
	return func(s *Server) {
		s.Dialer = d
	}
}

//Server holds parameters for thr server
type Server struct {
	//Addr is the address to listen on for incomming connections
	Addr string

	//Auth is the Authenticator used for authentication
	Auth Authenticator

	//KeepAlive is the Duration for TCP keep alive if 0 then the KeepAlives are disabled
	KeepAlive time.Duration

	//Cmds are the Commands supported by the server
	Cmds []Command

	//Dialer is the Dialer used to create outgoing connections
	Dialer *net.Dialer

	//Listen is the listener used by the Bind Command
	Listen func(network, address string) (net.Listener, error)

	//ListenPacket is the listener used by the Bind Command
	ListenPacket func(network, address string) (net.PacketConn, error)

	mu       sync.RWMutex
	doneChan chan struct{}
	listener net.Listener
}

// ListenAndServe starts the SOCKS5 server on the given address with the given options
// if addrs is empty then it listen on port 0.0.0.0:1080, by default no authentication and only support
// for connect command for IPv4
func ListenAndServe(addr string, opts ...Option) error {
	if addr == "" {
		addr = ":1080"
	}
	s := &Server{Addr: addr, Cmds: []Command{CommandConnect}, Dialer: new(net.Dialer)}
	for _, opt := range opts {
		opt(s)
	}
	return s.ListenAndServe()
}

// ListenAndServe starts the SOCKS5 server on the given address with the given options
// if addrs is empty then it listen on port 1080, with no authentication and only support
// for connect command
func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

//Serve accepts connections from the given listener and closes the listener on exit
func (s *Server) Serve(l net.Listener) error {
	defer l.Close()
	s.checkDefaults()
	s.setNewListener(l)
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				//Perhaps add delay like net/http pkg
				continue
			}
			return err
		}

		if tc, ok := conn.(*net.TCPConn); ok {
			if s.KeepAlive > 0 {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(s.KeepAlive)
			}
			conn := newConn(tc)
			go s.handleConnection(conn)

		}
	}
}

//Close closes the listener as well as all the underlying connections
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeDoneChanLocked()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) checkDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Dialer == nil {
		s.Dialer = new(net.Dialer)
	}
	if s.Auth == nil {
		s.Auth = NoAuth
	}

	if s.Listen == nil {
		s.Listen = net.Listen
	}

	if s.ListenPacket == nil {
		s.ListenPacket = net.ListenPacket
	}
}

func (s *Server) getDoneChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDoneChanLocked()
}

func (s *Server) getDoneChanLocked() chan struct{} {
	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}
	return s.doneChan
}

func (s *Server) closeDoneChanLocked() {
	ch := s.getDoneChanLocked()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (s *Server) setNewListener(l net.Listener) {
	defer s.mu.Unlock()
	s.mu.Lock()
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
	s.doneChan = nil
	s.listener = l
}

func (s *Server) handleConnection(c *conn) {
	defer func() {
		c.Close()
	}()

	if err := c.Negoatiate(s.Auth.AuthMethod()); err != nil {
		return
	}

	if err := s.Auth.Authenticate(c); err != nil {
		return
	}

	cmd, addr, err := c.ReadCommandRequest()
	if err != nil {
		switch err {
		case ErrInvalidSocksVer:
			c.WriteError(responseGeneralFailure)
			return
		case ErrAddressTypeNotSupported:
			c.WriteError(responseAddressNotSupported)
			return
		}
		return
	}
	log.Println(cmd, addr, err)
	switch cmd {
	case CommandConnect:
		s.handleConnect(c, addr)
	case CommandBind:
		s.handleBind(c, addr)
	case CommandUDPAssociation:
		s.handleUDPAssociation(c, addr)
	default:
		c.WriteError(responseCommandNotSupported)
	}
}

//handles connect command
func (s *Server) handleConnect(c *conn, addr net.Addr) error {
	t, err := s.Dialer.Dial("tcp", addr.String())
	if err != nil {
		c.WriteError(responseHostUnreachable)
		return err
	}
	err = c.WriteCommandResponse(responseSuccess, t.LocalAddr().String())
	if err != nil {
		return err
	}
	c.Relay(t)
	return nil
}

//handles bind commmand
func (s *Server) handleBind(c *conn, addr net.Addr) error {
	log.Println("Bind", addr)
	l, err := s.Listen("tcp", addr.String())
	if err != nil {
		c.WriteError(responseGeneralFailure)
		return err
	}

	err = c.WriteCommandResponse(responseSuccess, l.Addr().String())
	if err != nil {
		return err
	}

	nc, err := l.Accept()
	if err != nil {
		c.WriteError(responseGeneralFailure)
	}

	err = c.WriteCommandResponse(responseSuccess, nc.RemoteAddr().String())
	if err != nil {
		return err
	}
	c.Relay(nc)
	return nil
}

//TODO implement later
func (s *Server) handleUDPAssociation(c *conn, addr net.Addr) error {
	c.WriteError(responseCommandNotSupported)
	// l, err := s.ListenPacket("udp", "")
	// if err != nil {
	// 	c.WriteError(responseGeneralFailure)
	// 	return err
	// }
	// err = c.WriteCommandResponse(responseSuccess, l.LocalAddr().String()) //Use host
	// if err != nil {
	// 	return err
	// }

	// go func() {
	// 	defer func() {
	// 		recover()
	// 	}()
	// 	buf := make([]byte, 65536)
	// 	for {
	// 		n, _, err := l.ReadFrom(buf)

	// 		if err != nil || n < 7 {
	// 			continue
	// 		}

	// 		//two reserve bytes and one fragment number
	// 		if !bytes.Equal(buf[:3], []byte{0, 0, 0}) {
	// 			continue
	// 		}

	// 		addrLength := 0
	// 		domain := false
	// 		offset := 4

	// 		switch AddrType(c.buf[3]) {
	// 		case AddrTypeIPv4:
	// 			addrLength = net.IPv4len
	// 		case AddrTypeIPv6:
	// 			addrLength = net.IPv6len

	// 		case AddrTypeDomain:
	// 			addrLength = int(c.buf[4])
	// 			domain = true
	// 			offset++
	// 		default:
	// 			continue
	// 		}

	// 		addrBytes := buf[offset : offset+addrLength+1]

	// 		port := int(binary.BigEndian.Uint16(c.buf[offset+addrLength+1 : offset+addrLength+2]))

	// 		targetHost := string(addrBytes)

	// 		if !domain {
	// 			ip := net.IP(addrBytes)
	// 			targetHost = ip.String()
	// 		}

	// 		raddr := net.JoinHostPort(targetHost, strconv.Itoa(port))

	// 		rconn, err := net.Dial("udp", raddr)
	// 		if err != nil { //not sure
	// 			continue
	// 		}
	// 		_, err = rconn.Write(buf[offset+addrLength+2 : n])
	// 		if err != nil { //not sure
	// 			continue
	// 		}
	// 	}

	// }()

	// err = c.WriteCommandResponse(responseSuccess, l.LocalAddr().String())
	// if err != nil {
	// 	return err
	// }
	return nil
}
