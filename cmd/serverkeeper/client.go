package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tb12as/serverman/internal/agent"
	"github.com/tb12as/serverman/internal/config"
)

// client is the thin CLI client over the REST API (§10: behaviour never diverges).
type client struct {
	base  string
	token string
	hc    *http.Client
}

func newClient() (*client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	return newClientFor(cfg, flagAPI)
}

func newClientFor(cfg *config.Config, base string) (*client, error) {
	if base == "" {
		base = os.Getenv("SK_API")
	}
	if base == "" {
		scheme := "http"
		if cfg.TLS.Cert != "" {
			scheme = "https"
		}
		base = scheme + "://" + cfg.Listen
	}
	tok := flagToken
	if tok == "" {
		tok = os.Getenv("SK_TOKEN")
	}
	if tok == "" {
		b, err := os.ReadFile(agent.CLITokenPath(cfg))
		if err != nil {
			return nil, fmt.Errorf("no API token: run as root on the agent host (reads %s), or pass --token / SK_TOKEN",
				agent.CLITokenPath(cfg))
		}
		tok = strings.TrimSpace(string(b))
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: flagInsecure}}
	return &client{base: strings.TrimRight(base, "/") + "/api/v1", token: tok, hc: &http.Client{Transport: tr, Timeout: 5 * time.Minute}}, nil
}

func (c *client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach agent at %s: %w (is `serverkeeper agent run` / the systemd unit running?)", c.base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", e.Error, resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	if p, ok := out.(*[]byte); ok {
		*p = raw
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *client) get(path string, q url.Values, out any) error {
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return c.do(http.MethodGet, path, nil, out)
}

// raw performs a request and returns the body bytes (for exports, reports).
func (c *client) raw(method, path string, body any) ([]byte, error) {
	var b []byte
	err := c.do(method, path, body, &b)
	return b, err
}

// printJSON pretty-prints v.
func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// table returns a tabwriter on stdout; call Flush.
func table(headers ...string) *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	return w
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}
