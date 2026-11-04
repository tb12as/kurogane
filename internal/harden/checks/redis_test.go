package checks

import (
	"context"
	"strings"
	"testing"
)

func redisFile(c string) map[string]string { return map[string]string{"/etc/redis/redis.conf": c} }

func redisCases() []scanCase {
	pub := []Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 6379}}
	local := []Listener{{Proto: "tcp", Addr: "127.0.0.1", Port: 6379}}
	renamed := "bind 0.0.0.0\nrequirepass pw\nrename-command FLUSHALL \"\"\nrename-command FLUSHDB \"\"\n" +
		"rename-command CONFIG \"\"\nrename-command DEBUG \"\"\n"
	return []scanCase{
		{"loopback", "REDIS-NOT-EXPOSED", Fixture{Files: redisFile("bind 127.0.0.1 -::1\n")}, Pass},
		{"exposed with password", "REDIS-NOT-EXPOSED", Fixture{Files: redisFile("bind 0.0.0.0\nrequirepass pw\n")}, Pass},
		{"exposed by bind", "REDIS-NOT-EXPOSED", Fixture{Files: redisFile("bind 0.0.0.0\n")}, Fail},
		{"no bind", "REDIS-NOT-EXPOSED", Fixture{Files: redisFile("port 6379\n")}, Fail},
		{"live listener", "REDIS-NOT-EXPOSED", Fixture{Files: redisFile("bind 127.0.0.1\n"), Listen: pub}, Fail},
		{"live loopback", "REDIS-NOT-EXPOSED", Fixture{Files: redisFile("port 6379\n"), Listen: local}, Pass},
		{"none", "REDIS-NOT-EXPOSED", Fixture{}, NA},
		{"requirepass", "REDIS-AUTH", Fixture{Files: redisFile("requirepass \"x y\"\n")}, Pass},
		{"acl default off", "REDIS-AUTH", Fixture{Files: map[string]string{
			"/etc/redis/redis.conf": "aclfile /etc/redis/users.acl\n",
			"/etc/redis/users.acl":  "user default off\nuser app on >pw ~* +@all\n"}}, Pass},
		{"acl nopass", "REDIS-AUTH", Fixture{Files: redisFile("user default on nopass ~* +@all\nrequirepass x\n")}, Fail},
		{"none set", "REDIS-AUTH", Fixture{Files: redisFile("bind 127.0.0.1\n")}, Fail},
		{"default", "REDIS-PROTECTED-MODE", Fixture{Files: redisFile("bind 127.0.0.1\n")}, Pass},
		{"off", "REDIS-PROTECTED-MODE", Fixture{Files: redisFile("protected-mode no\n")}, Fail},
		{"loopback", "REDIS-DANGEROUS-COMMANDS", Fixture{Files: redisFile("bind 127.0.0.1\n")}, Pass},
		{"renamed", "REDIS-DANGEROUS-COMMANDS", Fixture{Files: redisFile(renamed)}, Pass},
		{"acl users", "REDIS-DANGEROUS-COMMANDS", Fixture{Files: redisFile("bind 0.0.0.0\nuser app on >pw ~* +get\n")}, Pass},
		{"open", "REDIS-DANGEROUS-COMMANDS", Fixture{Files: redisFile("bind 0.0.0.0\nrequirepass pw\n")}, Fail},
	}
}

func TestRedisEvidence(t *testing.T) {
	e, _ := Setup(t, Fixture{Files: map[string]string{
		"/etc/redis/redis.conf":       "bind 0.0.0.0\nprotected-mode no\n",
		"/etc/redis/redis-cache.conf": "bind 127.0.0.1\nrequirepass pw\n",
	}})
	run := func(id string) Result { return find(e, id).Run(WithMemo(context.Background())) }
	if r := run("REDIS-NOT-EXPOSED"); r.Status != Fail || !strings.Contains(r.Evidence, "/etc/redis/redis.conf listens on 0.0.0.0 with no password") ||
		strings.Contains(r.Evidence, "redis-cache") {
		t.Errorf("exposed = %+v", r)
	}
	if r := run("REDIS-PROTECTED-MODE"); r.Evidence != "protected-mode no at /etc/redis/redis.conf:2" {
		t.Errorf("protected = %+v", r)
	}
	if r := run("REDIS-AUTH"); !strings.Contains(r.Evidence, "/etc/redis/redis.conf: no requirepass") {
		t.Errorf("auth = %+v", r)
	}
	if r := run("REDIS-DANGEROUS-COMMANDS"); !strings.Contains(r.Evidence, "FLUSHALL, FLUSHDB, CONFIG, DEBUG not renamed") {
		t.Errorf("dangerous = %+v", r)
	}
	// masked ACL lines never carry passwords
	if got := maskACL([]string{"app", "on", ">s3cret", "#abc", "~*"}); got != "app on >*** #*** ~*" {
		t.Errorf("mask = %q", got)
	}
}
