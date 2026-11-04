package redisinfo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()

// fakeServer answers RESP commands with handle(args) (raw RESP text) and records every command.
type fakeServer struct {
	addr string
	cmds chan []string
}

func serve(t *testing.T, handle func(args []string) string) *fakeServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeServer{addr: l.Addr().String(), cmds: make(chan []string, 100)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					args, err := readCmd(r)
					if err != nil {
						return
					}
					f.cmds <- args
					if _, err := io.WriteString(c, handle(args)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return f
}

func readCmd(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := r.ReadString('\n'); err != nil {
			return nil, err
		}
		v, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args = append(args, strings.TrimRight(v, "\r\n"))
	}
	return args, nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func TestDialAndInfo(t *testing.T) {
	info, err := os.ReadFile("testdata/info-7.2.txt")
	if err != nil {
		t.Fatal(err)
	}
	f := serve(t, func(a []string) string {
		switch strings.ToUpper(a[0]) {
		case "AUTH":
			if len(a) == 3 && a[1] == "serverkeeper" && a[2] == "s3cret" {
				return "+OK\r\n"
			}
			return "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
		case "PING":
			return "+PONG\r\n"
		case "INFO":
			return bulk(strings.ReplaceAll(string(info), "\n", "\r\n"))
		case "SLOWLOG":
			return "*2\r\n" +
				"*6\r\n:14\r\n:1762200000\r\n:25000\r\n*3\r\n" + bulk("set") + bulk("session:42") + bulk("secret-value") +
				bulk("10.0.0.9:5000") + bulk("") +
				"*4\r\n:13\r\n:1762199000\r\n:12000\r\n*3\r\n" + bulk("config") + bulk("set") + bulk("requirepass") + "\r\n"
		}
		return "-ERR unknown command\r\n"
	})
	c, err := Dial(ctx, Target{Addr: f.addr, Username: "serverkeeper", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := <-f.cmds; strings.Join(got, " ") != "AUTH serverkeeper s3cret" {
		t.Fatalf("first command = %v", got)
	}
	if d, err := c.Ping(); err != nil || d <= 0 {
		t.Fatalf("ping = %v %v", d, err)
	}
	in, err := c.Info()
	if err != nil {
		t.Fatal(err)
	}
	if in["redis_version"] != "7.2.4" || in.Num("used_memory") != 104857600 || in.Num("mem_fragmentation_ratio") != 1.2 ||
		in["role"] != "master" || in.Num("missing") != 0 {
		t.Fatalf("info = %v", in)
	}
	if _, ok := in.Float("maxmemory_policy"); ok {
		t.Fatal("text parsed as a number")
	}
	ks := in.Keyspace()
	if len(ks) != 3 || ks[0] != (DB{Name: "db0", Keys: 1500, Expires: 200}) || ks[1].Name != "db2" || ks[2].Name != "db10" {
		t.Fatalf("keyspace = %+v", ks)
	}
	sl, err := c.SlowLog(10)
	if err != nil || len(sl) != 2 {
		t.Fatalf("slowlog = %+v %v", sl, err)
	}
	if sl[0].Command != "SET" || sl[0].Duration != 25*time.Millisecond || sl[0].ID != 14 || sl[1].Command != "CONFIG SET" {
		t.Fatalf("slowlog = %+v", sl)
	}
	for _, e := range sl {
		if strings.Contains(e.Command, "secret") || strings.Contains(e.Command, "session") || strings.Contains(e.Command, "requirepass") {
			t.Fatalf("slowlog leaked arguments: %+v", e)
		}
	}
}

func TestAuthOutcomes(t *testing.T) {
	needs := serve(t, func(a []string) string {
		if a[0] == "AUTH" {
			return "-WRONGPASS invalid username-password pair\r\n"
		}
		return "-NOAUTH Authentication required.\r\n"
	})
	if _, err := Dial(ctx, Target{Addr: needs.addr}); !errors.Is(err, ErrNoAuth) {
		t.Fatalf("no password: %v", err)
	}
	if _, err := Dial(ctx, Target{Addr: needs.addr, Password: "wrong"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password: %v", err)
	}
	open := serve(t, func(a []string) string {
		if a[0] == "AUTH" {
			return "-ERR AUTH <password> called without any password configured for the default user.\r\n"
		}
		return "+PONG\r\n"
	})
	c, err := Dial(ctx, Target{Addr: open.addr, Password: "unneeded"})
	if err != nil {
		t.Fatalf("unneeded password: %v", err)
	}
	c.Close()
}

func TestProtocolErrors(t *testing.T) {
	for name, reply := range map[string]string{
		"bad type":   "?what\r\n",
		"bad bulk":   "$x\r\n",
		"huge bulk":  "$99999999\r\n",
		"bad array":  "*x\r\n",
		"empty line": "\r\n",
	} {
		f := serve(t, func([]string) string { return reply })
		if _, err := Dial(ctx, Target{Addr: f.addr}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// null bulk and integers parse
	f := serve(t, func(a []string) string {
		if a[0] == "PING" {
			return "+PONG\r\n"
		}
		return "*3\r\n$-1\r\n:7\r\n*-1\r\n"
	})
	c, err := Dial(ctx, Target{Addr: f.addr})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Do("X")
	if arr, ok := v.([]any); err != nil || !ok || len(arr) != 3 || arr[0] != nil || arr[1] != int64(7) || arr[2] != nil {
		t.Fatalf("do = %#v %v", v, err)
	}
	if _, err := c.Info(); err == nil {
		t.Fatal("INFO returning an array must fail")
	}
	c.Close()
}

func TestTimeoutAndUnix(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	start := time.Now()
	if _, err := Dial(ctx, Target{Addr: l.Addr().String(), Timeout: 100 * time.Millisecond}); err == nil ||
		time.Since(start) > 900*time.Millisecond {
		t.Fatalf("timeout not honoured: %v after %v", err, time.Since(start))
	}
	sock := t.TempDir() + "/r.sock"
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets unavailable")
	}
	defer ul.Close()
	go func() {
		c, err := ul.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		if _, err := readCmd(r); err == nil {
			io.WriteString(c, "+PONG\r\n")
		}
	}()
	c, err := Dial(ctx, Target{Addr: "unix:" + sock})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
