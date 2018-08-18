package socks5

import (
	"bytes"
	"testing"
)

func TestSocksAddrNew(t *testing.T) {
	tts := []struct {
		addr      string
		socksAddr *socksAddr
	}{
		{"0.0.0.0:0", &socksAddr{Type: AddrTypeIPv4, Addr: "0.0.0.0:0"}},
		{"1.2.3.4:5", &socksAddr{Type: AddrTypeIPv4, Addr: "1.2.3.4:5"}},
		{"google.com:80", &socksAddr{Type: AddrTypeDomain, Addr: "google.com:80"}},
		{"[::]:80", &socksAddr{Type: AddrTypeIPv6, Addr: "[::]:80"}},
		{"[2001:db8::a:b:c:d]:80", &socksAddr{Type: AddrTypeIPv6, Addr: "[2001:db8::a:b:c:d]:80"}},
	}

	for _, tt := range tts {
		s := newAddr(tt.addr)
		if s == nil || s.Addr != tt.socksAddr.Addr || s.Type != tt.socksAddr.Type {
			t.Fail()
		}
	}
}

func TestSocksAddrMarshal(t *testing.T) {
	tts := []struct {
		addr   *socksAddr
		result []byte
	}{
		{&socksAddr{Type: AddrTypeIPv4, Addr: "0.0.0.0:0"}, []byte{1, 0, 0, 0, 0, 0, 0}},
		{&socksAddr{Type: AddrTypeIPv4, Addr: "1.2.3.4:5"}, []byte{1, 1, 2, 3, 4, 0, 5}},
		{&socksAddr{Type: AddrTypeDomain, Addr: "google.com:80"}, []byte{3, 10, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 0, 80}},
		{&socksAddr{Type: AddrTypeIPv6, Addr: "[::]:80"}, []byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80}},
		{&socksAddr{Type: AddrTypeIPv6, Addr: "[2001:db8::a:b:c:d]:80"}, []byte{4, 32, 1, 13, 184, 0, 0, 0, 0, 0, 10, 0, 11, 0, 12, 0, 13, 0, 80}},
	}

	for _, tt := range tts {
		b := make([]byte, 256)
		n, err := tt.addr.Marshal(b)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(b[:n], tt.result) {
			t.Fail()
		}
	}
}

func TestSocksAddrMarshalErrors(t *testing.T) {
	tts := []struct {
		addr *socksAddr
		size int
	}{
		{&socksAddr{Type: AddrTypeIPv4, Addr: "0.0.0.0:0"}, 5},
		{&socksAddr{Type: AddrTypeDomain, Addr: "1.2.3.4:a"}, 256},
		{&socksAddr{Type: AddrTypeIPv4, Addr: "google.com:80"}, 256},
		{&socksAddr{Type: AddrTypeIPv4, Addr: "google.com"}, 256},
	}

	for _, tt := range tts {
		b := make([]byte, tt.size)
		n, err := tt.addr.Marshal(b)
		if err == nil || n > 0 {
			t.Error(err, n, tt.addr)
		}
	}
}
