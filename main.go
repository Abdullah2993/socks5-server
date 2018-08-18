package main

import (
	"flag"
	"log"
	"net"

	igd "github.com/abdullah2993/go-fwdlistener"
	"github.com/abdullah2993/socks5-server/socks5"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
}

func main() {
	var addr, user, pass, host string
	var upnp bool

	flag.StringVar(&addr, "addr", "192.168.8.138:5555", "port to listen on")
	flag.StringVar(&user, "username", "", "username for authentication")
	flag.StringVar(&pass, "password", "", "password for authentication")
	flag.StringVar(&host, "host", "", "host used for incomming connections")
	flag.BoolVar(&upnp, "upnp", false, "use upnp")

	flag.Parse()

	opts := []socks5.Option{}

	var err error
	if user != "" || pass != "" {
		opts = append(opts, socks5.WithAuth(user, pass))
	}

	if host != "" {
		opts = append(opts, socks5.WithAddrProvider(HostAddrProvider(host)))
	}

	if upnp {
		opts = append(opts, socks5.WithListener(igd.Listen), socks5.WithPacketListener(igd.ListenPacket))
	}

	err = socks5.ListenAndServe(addr, opts...)

	log.Fatalf("server failed: %v", err)
}

//HostAddrProvider is an adapter for address provider
func HostAddrProvider(host string) socks5.AddrProvider {
	return func(addr net.Addr) string {
		_, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return net.JoinHostPort(host, port)
	}
}
