// Package capture classifies the first bytes of a proxied TCP stream at the
// connection level only: TLS ClientHello metadata (SNI/ALPN), plain-HTTP
// detection, or opaque TCP. It never decrypts or reassembles content.
package capture

import (
	"bufio"
	"bytes"
	"io"
	"time"
)

// Info is the connection-level classification of a stream.
type Info struct {
	Proto string   // "TLS", "HTTP", "SSH", or "TCP"
	SNI   string   // from TLS ClientHello, if present
	ALPN  []string // from TLS ClientHello, if present
}

// Classify peeks at the first bytes available on r (with an existing read
// deadline expected to be set by the caller) and returns the connection
// level classification. It never blocks longer than ~30ms beyond the first
// byte: after the first byte arrives we give the local client a beat to
// flush its first flight, then classify whatever is buffered.
func Classify(r io.Reader) (Info, *PrefixConn, error) {
	br := bufio.NewReader(r)
	if _, err := br.Peek(1); err != nil {
		// client sent nothing (server-first protocol or idle): opaque
		return Info{Proto: "TCP"}, &PrefixConn{R: br}, nil
	}
	time.Sleep(30 * time.Millisecond) // let the first flight arrive
	peek, _ := br.Peek(br.Buffered())
	pc := &PrefixConn{R: br}
	if len(peek) >= 2 && peek[0] == 0x16 && peek[1] == 0x03 {
		info := Info{Proto: "TLS"}
		if sni, alpn := parseClientHello(peek); sni != "" || len(alpn) > 0 {
			info.SNI, info.ALPN = sni, alpn
		}
		return info, pc, nil
	}
	if bytes.HasPrefix(peek, []byte("SSH-")) {
		return Info{Proto: "SSH"}, pc, nil
	}
	if isHTTPRequestLine(peek) {
		return Info{Proto: "HTTP"}, pc, nil
	}
	return Info{Proto: "TCP"}, pc, nil
}

// PrefixConn replays nothing itself; it just marks that the underlying
// bufio.Reader still holds peeked bytes which will be read first.
type PrefixConn struct {
	R *bufio.Reader
}

// common HTTP methods seen at the start of a request line.
var httpMethods = []string{
	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
	"PATCH ", "CONNECT ", "TRACE ",
}

func isHTTPRequestLine(p []byte) bool {
	line := p
	if i := bytes.Index(line, []byte("\r\n")); i >= 0 {
		line = line[:i]
	} else if len(line) > 128 {
		line = line[:128]
	}
	upper := bytes.ToUpper(line)
	for _, m := range httpMethods {
		if bytes.HasPrefix(upper, []byte(m)) && bytes.Contains(line, []byte("HTTP/")) {
			return true
		}
	}
	return false
}

// parseClientHello extracts SNI and ALPN from a TLS ClientHello record.
// It is deliberately lenient: any parse failure yields empty results.
func parseClientHello(p []byte) (sni string, alpn []string) {
	defer func() { _ = recover() }()
	if len(p) < 5 || p[0] != 0x16 {
		return "", nil
	}
	recLen := int(p[3])<<8 | int(p[4])
	if len(p) < 5+recLen {
		// truncated peek; parse what we have
		recLen = len(p) - 5
	}
	hs := p[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 { // ClientHello
		return "", nil
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if len(body) < hsLen {
		hsLen = len(body)
	}
	body = body[:hsLen]
	// version(2) + random(32)
	if len(body) < 34 {
		return "", nil
	}
	rest := body[34:]
	// session id
	if len(rest) < 1 {
		return "", nil
	}
	l := int(rest[0])
	rest = rest[1:]
	if len(rest) < l {
		return "", nil
	}
	rest = rest[l:]
	// cipher suites
	if len(rest) < 2 {
		return "", nil
	}
	l = int(rest[0])<<8 | int(rest[1])
	rest = rest[2:]
	if len(rest) < l {
		return "", nil
	}
	rest = rest[l:]
	// compression methods
	if len(rest) < 1 {
		return "", nil
	}
	l = int(rest[0])
	rest = rest[1:]
	if len(rest) < l {
		return "", nil
	}
	rest = rest[l:]
	// extensions
	if len(rest) < 2 {
		return "", nil
	}
	extLen := int(rest[0])<<8 | int(rest[1])
	rest = rest[2:]
	if len(rest) < extLen {
		extLen = len(rest)
	}
	exts := rest[:extLen]
	for len(exts) >= 4 {
		typ := int(exts[0])<<8 | int(exts[1])
		el := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if len(exts) < el {
			break
		}
		data := exts[:el]
		exts = exts[el:]
		switch typ {
		case 0x0000: // server_name
			if s := parseSNI(data); s != "" {
				sni = s
			}
		case 0x0010: // ALPN
			alpn = parseALPN(data)
		}
	}
	return sni, alpn
}

func parseSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	l := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < l {
		return ""
	}
	list := data[:l]
	for len(list) >= 3 {
		nameType := list[0]
		nl := int(list[1])<<8 | int(list[2])
		list = list[3:]
		if len(list) < nl {
			return ""
		}
		if nameType == 0 {
			return string(list[:nl])
		}
		list = list[nl:]
	}
	return ""
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	l := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < l {
		return nil
	}
	list := data[:l]
	var out []string
	for len(list) >= 1 {
		nl := int(list[0])
		list = list[1:]
		if len(list) < nl {
			break
		}
		out = append(out, string(list[:nl]))
		list = list[nl:]
	}
	return out
}
