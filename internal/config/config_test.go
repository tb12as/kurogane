package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sample = `
server_name: web-01
tags: [prod, web]
listen: 127.0.0.1:9443
collector:
  interval: 10s
  retention_raw: 24h
  retention_rollup: 7d
  watch_services: [nginx, mysql, docker]
ssh:
  rollback_timeout: 120s
  bruteforce:
    enabled: true
    max_failures: 5
    window: 10m
    ban_for: 1h
    allowlist: [203.0.113.10/32]
harden:
  schedule: "0 3 * * *"
  ignore:
    - id: SSH-PORT-NONDEFAULT
      reason: "Port 22 required by provider console"
alerts:
  channels:
    - name: ops
      type: slack
      webhook_url_env: SK_SLACK_OPS
    - name: phone
      type: discord
      webhook_url_env: SK_DISCORD_ME
  rules:
    - id: mem_available_low
      expr: mem.available_pct < 10
      for: 5m
      severity: warning
      channels: [ops, phone]
  repeat_interval: 30m
`

func TestLoadPRDExample(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(sample), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerName != "web-01" || c.Collector.RetentionRollup != 7*24*time.Hour || len(c.Alerts.Rules) != 1 ||
		c.Alerts.Rules[0].For != 5*time.Minute || c.SSH.Bruteforce.Allowlist[0] != "203.0.113.10/32" {
		t.Fatalf("bad config: %+v", c)
	}
}

func TestRemoteNeedsTLS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte("listen: 0.0.0.0:9443\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("non-loopback listen without TLS must fail")
	}
}

func TestValidateAndDurations(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "90s": 90 * time.Second, "1.5d": 36 * time.Hour} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if _, err := ParseDuration("xd"); err == nil {
		t.Error("xd must fail")
	}
	dir := t.TempDir()
	for name, y := range map[string]string{
		"interval": "collector: {interval: 120s}\n",
		"rollback": "ssh: {rollback_timeout: 1s}\n",
		"dupchan":  "alerts: {channels: [{name: a, type: slack}, {name: a, type: slack}]}\n",
		"badtype":  "alerts: {channels: [{name: a, type: sms}]}\n",
		"noreason": "harden: {ignore: [{id: X}]}\n",
		"yaml":     "listen: [\n",
	} {
		p := filepath.Join(dir, name+".yaml")
		os.WriteFile(p, []byte(y), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	c, err := Load(filepath.Join(dir, "missing.yaml"))
	if err != nil || c.Listen != "127.0.0.1:9443" || c.AgentDB() == "" || c.MetaDB() == "" || c.BackupDir() == "" {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	if IsLoopback("localhost:1") != true || IsLoopback("0.0.0.0:1") || IsLoopback("bad") {
		t.Error("IsLoopback")
	}
}
