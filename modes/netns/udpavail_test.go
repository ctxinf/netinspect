package netns

import (
	"net"
	"testing"
	"time"
)

// udpAvailable reports whether UDP loopback round-trips work in this
// environment (some sandboxes block UDP replies).
func udpAvailable() bool {
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 16)
		srv.SetDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := srv.ReadFrom(buf)
		if err != nil {
			return
		}
		srv.WriteTo(buf[:n], addr)
	}()
	c, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 16)
	_, err = c.Read(buf)
	return err == nil
}

func TestUDPAvailable(t *testing.T) {
	t.Logf("udpAvailable=%v", udpAvailable())
}
