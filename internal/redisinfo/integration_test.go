//go:build integration

package redisinfo

import (
	"errors"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// TestRealRedis runs against a throwaway redis-server (installed in the CI image) with a password, a read-only
// ACL user and a slow log that records everything.
func TestRealRedis(t *testing.T) {
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(bin, "--port", strconv.Itoa(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no",
		"--requirepass", "adminpw", "--slowlog-log-slower-than", "0",
		"--user", "kurogane", "on", ">readpw", "-@all", "+ping", "+info", "+slowlog|get", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var c *Conn
	for i := 0; i < 50; i++ {
		if c, err = Dial(ctx, Target{Addr: addr, Username: "kurogane", Password: "readpw"}); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in, err := c.Info()
	if err != nil || in["redis_version"] == "" || in["role"] != "master" || in.Num("uptime_in_seconds") < 0 {
		t.Fatalf("info = %v %v", in, err)
	}
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	sl, err := c.SlowLog(5)
	if err != nil || len(sl) == 0 || sl[0].Command == "" {
		t.Fatalf("slowlog = %+v %v", sl, err)
	}
	// the read-only user cannot do anything else
	if _, err := c.Do("SET", "k", "v"); err == nil {
		t.Fatal("ACL user could write")
	}
	if _, err := Dial(ctx, Target{Addr: addr}); !errors.Is(err, ErrNoAuth) {
		t.Fatalf("no password: %v", err)
	}
	if _, err := Dial(ctx, Target{Addr: addr, Password: "nope"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password: %v", err)
	}
}
