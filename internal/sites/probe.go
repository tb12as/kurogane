package sites

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"
)

// prober reports whether a site answers HTTP at all; any status code counts, including 404 and 502, because
// the question is whether the web server still serves the site, not whether the application behind it works.
type prober func(ctx context.Context, s Site) bool

// ProbeTimeout bounds one probe request.
var ProbeTimeout = 3 * time.Second

func httpProbe(ctx context.Context, s Site) bool {
	if len(s.Listen) == 0 {
		return false
	}
	l := s.Listen[0]
	host := "127.0.0.1"
	switch {
	case l.Addr == "::" || l.Addr == "[::]":
		host = "::1"
	case l.Addr != "" && l.Addr != "*" && net.ParseIP(l.Addr) != nil:
		host = l.Addr
	}
	name := s.Name
	if name == "_" || name == "" || name[0] == '~' || name[0] == '*' {
		name = "localhost"
	}
	scheme := "http"
	if l.TLS {
		scheme = "https"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(l.Port))
	tr := &http.Transport{
		// dial the local address whatever the URL host is, so Host and SNI carry the site name
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: ProbeTimeout}).DialContext(ctx, network, addr)
		},
		TLSClientConfig:   &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- liveness probe of our own host
		DisableKeepAlives: true,
	}
	c := &http.Client{Transport: tr, Timeout: ProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+net.JoinHostPort(name, strconv.Itoa(l.Port))+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "serverkeeper-site-probe")
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}
