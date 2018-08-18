package main

import (
	"flag"
	"log"

	"github.com/abdullah2993/socks5-server/socks5"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
}

func main() {
	var addr, user, pass string

	flag.StringVar(&addr, "addr", "192.168.8.138:5555", "port to listen on")
	flag.StringVar(&user, "username", "", "username for authentication")
	flag.StringVar(&pass, "password", "", "password for authentication")

	flag.Parse()

	var err error
	if user != "" && pass != "" {
		err = socks5.ListenAndServe(addr, socks5.WithAuth(user, pass))
	}

	err = socks5.ListenAndServe(addr)

	log.Fatalf("server failed: %v", err)
}
