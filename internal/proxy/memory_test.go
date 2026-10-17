package proxy

import (
	"fmt"
	"io"
	"net"
	"netinspect/internal/store"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMemoryFullDoesNotInterruptProxy(t *testing.T) {
	st := store.NewWithLimit(store.Session{}, 8192)
	st.AddDNS(&store.DNSQuery{QName: "fills-budget.test"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1024)
		_, e = c.Read(buf)
		if e == nil {
			_, e = fmt.Fprint(c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
		done <- e
	}()
	px := New(Config{Mode: "test", Store: st})
	defer px.Close()
	client, proxyClient := net.Pipe()
	defer client.Close()
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	relayDone := make(chan struct{})
	go func() { defer close(relayDone); px.handleTransparent(proxyClient, host, port) }()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprint(client, "GET / HTTP/1.0\r\nHost: local.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	_, err = io.ReadFull(client, body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(body), "\r\n\r\nok") {
		t.Fatalf("relay failed: %q", body)
	}
	client.Close()
	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if m := st.Memory(); !m.Limited || m.Dropped != 1 {
		t.Fatalf("record limit not reached: %+v", m)
	}
	if len(st.ListConnections("", 1)) != 0 {
		t.Fatal("recorded beyond budget")
	}
}
