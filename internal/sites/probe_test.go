package sites

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/tb12as/kurogane/internal/webconf"
)

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(addr)
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHTTPProbe(t *testing.T) {
	var host string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { host = r.Host; w.WriteHeader(404) })
	plain := httptest.NewServer(h)
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(h)
	defer tlsSrv.Close()

	s := Site{Name: "shop.example.org", Listen: []webconf.Listen{{Port: portOf(t, plain.Listener.Addr().String())}}}
	if !httpProbe(ctx, s) || host != "shop.example.org:"+strconv.Itoa(s.Listen[0].Port) {
		t.Fatalf("plain probe failed (host %q)", host)
	}
	s = Site{Name: "_", Listen: []webconf.Listen{{Addr: "127.0.0.1", Port: portOf(t, tlsSrv.Listener.Addr().String()), TLS: true}}}
	if !httpProbe(ctx, s) {
		t.Fatal("tls probe failed")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := portOf(t, l.Addr().String())
	l.Close()
	if httpProbe(ctx, Site{Name: "x", Listen: []webconf.Listen{{Port: closed}}}) || httpProbe(ctx, Site{Name: "x"}) {
		t.Fatal("closed port answered")
	}
}
