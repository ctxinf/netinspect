package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NewUpstream configures an explicit TCP upstream. It never reads ambient proxy
// variables or falls back to a direct connection after an upstream failure.
func NewUpstream(raw string, markOutbound bool) (Upstream, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy URL")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("upstream proxy scheme must be http, https, socks5 or socks5h")
	}
	if u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, fmt.Errorf("upstream proxy requires a host and optional port/credentials, without path, query or fragment")
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "1080"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("upstream proxy port must be between 1 and 65535")
	}
	if u.User != nil && strings.HasPrefix(u.Scheme, "socks5") {
		password, _ := u.User.Password()
		if len(u.User.Username()) < 1 || len(u.User.Username()) > 255 || len(password) < 1 || len(password) > 255 {
			return nil, fmt.Errorf("SOCKS5 username and password must each contain 1–255 bytes")
		}
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	if markOutbound {
		dialer.Control = markControl
	}
	return &upstreamProxy{url: u, address: net.JoinHostPort(u.Hostname(), port), dialer: dialer}, nil
}

type upstreamProxy struct {
	url       *url.URL
	address   string
	dialer    net.Dialer
	tlsConfig *tls.Config // nil uses system trust; tests can supply a private CA
}

// Name deliberately excludes authentication information.
func (u *upstreamProxy) Name() string { return u.url.Scheme + "://" + u.address }

func (u *upstreamProxy) DialContext(ctx context.Context, network, address string) (result net.Conn, err error) {
	if network != "tcp" {
		return nil, fmt.Errorf("upstream proxy supports TCP only")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(address, "\r\n") {
		return nil, fmt.Errorf("invalid upstream target address")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid upstream target port")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := u.dialer.DialContext(ctx, "tcp", u.address)
	if err != nil {
		return nil, fmt.Errorf("upstream dial: %w", err)
	}
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(finished) })
	defer func() {
		if !stop() {
			<-finished
		}
		if ctx.Err() != nil {
			result, err = nil, ctx.Err()
		}
		if err != nil {
			conn.Close()
		} else if clearErr := conn.SetDeadline(time.Time{}); clearErr != nil {
			conn.Close()
			result, err = nil, clearErr
		}
	}()
	if strings.HasPrefix(u.url.Scheme, "socks5") {
		if u.url.Scheme == "socks5" && net.ParseIP(host) == nil {
			ips, resolveErr := net.DefaultResolver.LookupIPAddr(ctx, host)
			if resolveErr != nil {
				return nil, fmt.Errorf("upstream target resolve: %w", resolveErr)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("upstream target resolve: no addresses")
			}
			host = ips[0].IP.String()
		}
		if err = u.socksConnect(conn, host, p); err != nil {
			return nil, err
		}
		return conn, nil
	}
	tunnel := conn
	if u.url.Scheme == "https" {
		cfg := u.tlsConfig
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			cfg = cfg.Clone()
		}
		cfg.ServerName = u.url.Hostname()
		cfg.NextProtos = []string{"http/1.1"}
		secure := tls.Client(conn, cfg)
		if err = secure.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("upstream TLS: %w", err)
		}
		tunnel = secure
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if u.url.User != nil {
		password, _ := u.url.User.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(u.url.User.Username() + ":" + password))
		request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err = request.Write(tunnel); err != nil {
		return nil, fmt.Errorf("upstream CONNECT write: %w", err)
	}
	// Bound response headers and retain bytes read ahead from the tunnel.
	reader := bufio.NewReader(io.LimitReader(tunnel, 64<<10))
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("upstream CONNECT response: %w", err)
	}
	// RFC 9110: any 2xx response switches immediately to tunnel mode.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream CONNECT rejected (HTTP %d)", response.StatusCode)
	}
	return &bufferedUpstreamConn{Conn: tunnel, reader: io.MultiReader(reader, tunnel)}, nil
}

type bufferedUpstreamConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedUpstreamConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedUpstreamConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

// SOCKS5 CONNECT and username/password authentication (RFC 1928 / RFC 1929).
func (u *upstreamProxy) socksConnect(conn net.Conn, host string, port int) error {
	method := byte(0)
	if u.url.User != nil {
		method = 2
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != method {
		return fmt.Errorf("upstream SOCKS5 authentication method rejected")
	}
	if method == 2 {
		username := u.url.User.Username()
		password, _ := u.url.User.Password()
		auth := append([]byte{1, byte(len(username))}, []byte(username)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		if reply[0] != 1 || reply[1] != 0 {
			return fmt.Errorf("upstream SOCKS5 authentication failed")
		}
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 1)
			request = append(request, v4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("upstream SOCKS5 target hostname is too long")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 5 || header[2] != 0 {
		return fmt.Errorf("invalid upstream SOCKS5 reply")
	}
	if header[1] != 0 {
		return fmt.Errorf("upstream SOCKS5 CONNECT rejected (code %d)", header[1])
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		if _, err := io.ReadFull(conn, reply[:1]); err != nil {
			return err
		}
		length = int(reply[0])
	default:
		return fmt.Errorf("invalid upstream SOCKS5 bound address")
	}
	_, err := io.CopyN(io.Discard, conn, int64(length+2))
	return err
}
