package capture

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestClassifyTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan Info, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		info, _, _ := Classify(c)
		got <- info
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = tls.Client(c, &tls.Config{
		ServerName:         "example.com",
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	}).Handshake()
	select {
	case info := <-got:
		if info.Proto != "TLS" {
			t.Fatalf("proto=%q want tls", info.Proto)
		}
		if info.SNI != "example.com" {
			t.Fatalf("sni=%q want example.com", info.SNI)
		}
		if len(info.ALPN) != 2 || info.ALPN[0] != "h2" {
			t.Fatalf("alpn=%q", info.ALPN)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestClassifyHTTP(t *testing.T) {
	info, _, _ := Classify(bytes.NewReader([]byte("POST /api/x HTTP/1.1\r\nHost: a.com\r\nContent-Length: 3\r\n\r\nabc")))
	if info.Proto != "HTTP" {
		t.Fatalf("proto=%q want http", info.Proto)
	}
}

func TestClassifyOpaque(t *testing.T) {
	info, _, _ := Classify(bytes.NewReader([]byte{0x01, 0x02, 0x03}))
	if info.Proto != "TCP" {
		t.Fatalf("proto=%q want tcp", info.Proto)
	}
}

func TestClassifySSHBanner(t *testing.T) {
	info, _, _ := Classify(bytes.NewReader([]byte("SSH-2.0-OpenSSH_9.9\r\n")))
	if info.Proto != "SSH" {
		t.Fatalf("proto=%q want SSH", info.Proto)
	}
}
