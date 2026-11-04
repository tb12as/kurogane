package redisinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type dirReader string

func (d dirReader) ReadFile(p string) ([]byte, error) {
	return os.ReadFile(filepath.Join(string(d), p))
}

func TestParseConfig(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc/redis"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc/redis/redis.conf"), []byte(`# Debian default
bind 127.0.0.1 -::1
protected-mode yes
port 6380
unixsocket /run/redis/redis-server.sock
requirepass "s3cr et"
rename-command FLUSHALL ""
rename-command CONFIG cfg-x9
user kurogane on >readpw -@all +ping +info
include local.conf
`), 0o640)
	os.WriteFile(filepath.Join(dir, "etc/redis/local.conf"), []byte("port 6381\n"), 0o640)
	c, err := ParseConfig(dirReader(dir), "/etc/redis/redis.conf")
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 6381 || c.RequirePass != "s3cr et" || !c.HasPassword || !c.ProtectedMode || !c.Loopback() ||
		c.UnixSocket != "/run/redis/redis-server.sock" || c.Lines["requirepass"] != 6 {
		t.Fatalf("config = %+v", c)
	}
	if !reflect.DeepEqual(c.Renamed, map[string]string{"FLUSHALL": "", "CONFIG": "cfg-x9"}) {
		t.Fatalf("renamed = %v", c.Renamed)
	}
	if len(c.Users) != 1 || c.Users[0] != "kurogane on >*** -@all +ping +info" {
		t.Fatalf("users = %v", c.Users)
	}
	if tg := c.Target(); tg.Addr != "127.0.0.1:6381" || tg.TLS {
		t.Fatalf("target = %+v", tg)
	}
	if _, err := ParseConfig(dirReader(dir), "/nope"); err == nil {
		t.Fatal("missing file")
	}
}

func TestConfigTargetsAndExposure(t *testing.T) {
	for name, tc := range map[string]struct {
		c        Config
		target   Target
		loopback bool
	}{
		"no bind":      {Config{Port: 6379}, Target{Addr: "127.0.0.1:6379"}, false},
		"all":          {Config{Port: 6379, Bind: []string{"0.0.0.0"}}, Target{Addr: "127.0.0.1:6379"}, false},
		"private only": {Config{Port: 6379, Bind: []string{"10.0.0.5"}}, Target{Addr: "10.0.0.5:6379"}, false},
		"mixed":        {Config{Port: 6379, Bind: []string{"10.0.0.5", "::1"}}, Target{Addr: "[::1]:6379"}, false},
		"tls only":     {Config{TLSPort: 6380, Bind: []string{"127.0.0.1"}}, Target{Addr: "127.0.0.1:6380", TLS: true}, true},
		"socket only":  {Config{UnixSocket: "/run/r.sock", Bind: []string{"127.0.0.1"}}, Target{Addr: "unix:/run/r.sock"}, true},
		"nothing":      {Config{}, Target{}, false},
	} {
		if got := tc.c.Target(); got != tc.target {
			t.Errorf("%s: target = %+v, want %+v", name, got, tc.target)
		}
		if tc.c.Loopback() != tc.loopback {
			t.Errorf("%s: loopback = %v", name, tc.c.Loopback())
		}
	}
	if got := splitConf(`a "b c" 'd e' "x\"y" ""`); !reflect.DeepEqual(got, []string{"a", "b c", "d e", `x"y`, ""}) {
		t.Fatalf("split = %q", got)
	}
}
