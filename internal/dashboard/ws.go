// Minimal WebSocket server (text frames, server->client only) to avoid an
// extra dependency. Implements the opening handshake and unmasked text frames.
package dashboard

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"netinspect/internal/proxy"
)

var wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func (d *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if !isWSRequest(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	accept := wsAccept(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		conn.Close()
		return
	}
	rw.Flush()

	sub := d.hub.Subscribe()
	defer d.hub.Unsubscribe(sub)
	// detect client close
	go func() {
		_, _ = readWSFrame(conn) // blocks until close/error; then conn closes
		conn.Close()
	}()
	for e := range sub {
		msg := wsEventJSON(e)
		if msg == nil {
			continue
		}
		if err := writeWSFrame(conn, msg); err != nil {
			return
		}
	}
}

func isWSRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func wsEventJSON(e proxy.Event) []byte {
	m := map[string]any{"type": e.Type}
	switch e.Type {
	case "conn_new", "conn_update", "conn_closed":
		m["conn"] = e.Conn
	case "dns":
		m["dns"] = e.DNS
	default:
		return nil
	}
	// best effort; drop on marshal error
	bs, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return bs
}

func writeWSFrame(conn net.Conn, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x81 // FIN + text
	n := len(payload)
	var hlen int
	switch {
	case n < 126:
		hdr[1] = byte(n)
		hlen = 2
	case n < 65536:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hlen = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hlen = 10
	}
	if _, err := conn.Write(hdr[:hlen]); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// readWSFrame reads one client frame (only to detect close); content ignored.
func readWSFrame(conn net.Conn) (bool, error) {
	br := bufio.NewReader(conn)
	hdr := make([]byte, 2)
	if _, err := br.Read(hdr); err != nil {
		return false, err
	}
	opcode := hdr[0] & 0x0F
	if opcode == 0x08 {
		return true, nil
	}
	masked := hdr[1]&0x80 != 0
	length := int(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		br.Read(ext[:])
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		br.Read(ext[:])
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	if masked {
		var mask [4]byte
		br.Read(mask[:])
	}
	// discard
	for length > 0 {
		chunk := length
		if chunk > 4096 {
			chunk = 4096
		}
		tmp := make([]byte, chunk)
		n, err := br.Read(tmp)
		length -= n
		if err != nil {
			return false, err
		}
	}
	return false, nil
}
