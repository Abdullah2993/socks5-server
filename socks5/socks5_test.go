package socks5

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const testString = "Hello World"

//TODO remove hardcoded port numbers from socks and http server
func TestConnectCommand(t *testing.T) {
	go ListenAndServe("127.0.0.1:8088")
	go http.ListenAndServe("127.0.0.1:8089", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, testString)
	}))
	<-time.After(5 * time.Second)
	sendAndTestReq(t, "http://127.0.0.1:8089", "socks5://127.0.0.1:8088")
}

func TestConnectCommandWithAuth(t *testing.T) {
	go ListenAndServe("127.0.0.1:8087", WithAuth("username", "password"))

	go http.ListenAndServe("127.0.0.1:8086", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, testString)
	}))
	<-time.After(5 * time.Second)

	sendAndTestReq(t, "http://127.0.0.1:8086", "socks5://username:password@127.0.0.1:8087")
}

func sendAndTestReq(t *testing.T, addr, proxy string) {
	c := http.Client{Transport: &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse(proxy)
		},
	}}

	res, err := c.Get(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != testString {
		t.Fail()
	}
}
