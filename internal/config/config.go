// Package config loads /etc/serverkeeper/config.yaml (PRD §10.3) with viper.
package config

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const DefaultPath = "/etc/serverkeeper/config.yaml"

type Config struct {
	ServerName   string    `mapstructure:"server_name" json:"server_name"`
	Tags         []string  `mapstructure:"tags" json:"tags"`
	Listen       string    `mapstructure:"listen" json:"listen"`
	DataDir      string    `mapstructure:"data_dir" json:"data_dir"`
	DashboardURL string    `mapstructure:"dashboard_url" json:"dashboard_url"`
	SecretKey    string    `mapstructure:"secret_key" json:"secret_key"`
	Privsep      bool      `mapstructure:"privsep" json:"privsep"`
	TLS          TLS       `mapstructure:"tls" json:"tls"`
	Collector    Collector `mapstructure:"collector" json:"collector"`
	SSH          SSH       `mapstructure:"ssh" json:"ssh"`
	Harden       Harden    `mapstructure:"harden" json:"harden"`
	Alerts       Alerts    `mapstructure:"alerts" json:"alerts"`
	Central      Central   `mapstructure:"central" json:"central"`
	Server       Server    `mapstructure:"server" json:"server"`
	Auth         Auth      `mapstructure:"auth" json:"auth"`
	Telemetry    Telemetry `mapstructure:"telemetry" json:"telemetry"`
	Web          Web       `mapstructure:"web" json:"web"`
}

// Web configures nginx/Apache site management.
type Web struct {
	Enabled bool `mapstructure:"enabled" json:"enabled"`
}

// TLS enables remote access; required whenever listen is not loopback (§11.1).
type TLS struct {
	Cert        string `mapstructure:"cert" json:"cert"`
	Key         string `mapstructure:"key" json:"key"`
	AllowRemote bool   `mapstructure:"allow_remote" json:"allow_remote"`
}

type Collector struct {
	Interval        time.Duration `mapstructure:"interval" json:"interval"`
	RetentionRaw    time.Duration `mapstructure:"retention_raw" json:"retention_raw"`
	RetentionRollup time.Duration `mapstructure:"retention_rollup" json:"retention_rollup"`
	WatchServices   []string      `mapstructure:"watch_services" json:"watch_services"`
	NginxLog        string        `mapstructure:"nginx_log" json:"nginx_log"`
	Prometheus      bool          `mapstructure:"prometheus" json:"prometheus"`
	Certs           Certs         `mapstructure:"certs" json:"certs"`
	Redis           Redis         `mapstructure:"redis" json:"redis"`
}

// Redis configures Redis monitoring.
type Redis struct {
	// Enabled is "auto" (monitor when a Redis config exists and its unit is enabled or its port answers),
	// "true" or "false". YAML booleans are accepted too.
	Enabled   string          `mapstructure:"enabled" json:"enabled"`
	Instances []RedisInstance `mapstructure:"instances" json:"instances"` // empty = autodetect
}

// RedisInstance is one explicitly configured Redis.
type RedisInstance struct {
	Name         string `mapstructure:"name" json:"name"`
	Addr         string `mapstructure:"addr" json:"addr"` // host:port or unix:/path
	Username     string `mapstructure:"username" json:"username"`
	PasswordFile string `mapstructure:"password_file" json:"password_file"`
	TLS          bool   `mapstructure:"tls" json:"tls"`
}

// Mode normalizes Enabled to "auto", "on" or "off".
func (r Redis) Mode() string {
	switch strings.ToLower(strings.TrimSpace(r.Enabled)) {
	case "", "auto":
		return "auto"
	case "true", "1", "yes", "on":
		return "on"
	case "false", "0", "no", "off":
		return "off"
	}
	return ""
}

// Certs configures TLS certificate expiry monitoring.
type Certs struct {
	Enabled    bool          `mapstructure:"enabled" json:"enabled"`
	Paths      []string      `mapstructure:"paths" json:"paths"`             // extra PEM files
	ProbePorts []int         `mapstructure:"probe_ports" json:"probe_ports"` // local TLS handshakes; empty disables
	Interval   time.Duration `mapstructure:"interval" json:"interval"`
}

type SSH struct {
	ConfigPath      string        `mapstructure:"config_path" json:"config_path"`
	RollbackTimeout time.Duration `mapstructure:"rollback_timeout" json:"rollback_timeout"`
	Bruteforce      Bruteforce    `mapstructure:"bruteforce" json:"bruteforce"`
	CA              SSHCA         `mapstructure:"ca" json:"ca"`
}

type Bruteforce struct {
	Enabled     bool          `mapstructure:"enabled" json:"enabled"`
	MaxFailures int           `mapstructure:"max_failures" json:"max_failures"`
	Window      time.Duration `mapstructure:"window" json:"window"`
	BanFor      time.Duration `mapstructure:"ban_for" json:"ban_for"`
	Allowlist   []string      `mapstructure:"allowlist" json:"allowlist"`
}

type SSHCA struct {
	MaxTTL     time.Duration `mapstructure:"max_ttl" json:"max_ttl"`
	DefaultTTL time.Duration `mapstructure:"default_ttl" json:"default_ttl"`
}

type Harden struct {
	Schedule      string   `mapstructure:"schedule" json:"schedule"`
	Ignore        []Ignore `mapstructure:"ignore" json:"ignore"`
	Packs         []string `mapstructure:"packs" json:"packs"`
	ExpectedPorts []int    `mapstructure:"expected_ports" json:"expected_ports"`
}

type Ignore struct {
	ID     string `mapstructure:"id" json:"id"`
	Reason string `mapstructure:"reason" json:"reason"`
}

type Alerts struct {
	Channels          []Channel           `mapstructure:"channels" json:"channels"`
	Rules             []Rule              `mapstructure:"rules" json:"rules"`
	RepeatInterval    time.Duration       `mapstructure:"repeat_interval" json:"repeat_interval"`
	RateLimit         int                 `mapstructure:"rate_limit" json:"rate_limit"`
	Routing           map[string][]string `mapstructure:"routing" json:"routing"`
	Thresholds        map[string]float64  `mapstructure:"thresholds" json:"thresholds"`
	DisableBuiltin    []string            `mapstructure:"disable_builtin" json:"disable_builtin"`
	AutoBan           AutoBan             `mapstructure:"auto_ban" json:"auto_ban"`
	NewLoginOnlyNewIP bool                `mapstructure:"new_login_only_new_ip" json:"new_login_only_new_ip"`
	NewLoginOnlyRoot  bool                `mapstructure:"new_login_only_root" json:"new_login_only_root"`
}

type Channel struct {
	Name          string   `mapstructure:"name" json:"name"`
	Type          string   `mapstructure:"type" json:"type"` // slack|discord|telegram|email|pagerduty|webhook
	WebhookURLEnv string   `mapstructure:"webhook_url_env" json:"webhook_url_env,omitempty"`
	WebhookURL    string   `mapstructure:"webhook_url" json:"-"` // "enc:..." encrypted, never plain in logs
	ChatID        string   `mapstructure:"chat_id" json:"chat_id,omitempty"`
	To            []string `mapstructure:"to" json:"to,omitempty"`
	SMTPAddr      string   `mapstructure:"smtp_addr" json:"smtp_addr,omitempty"`
	SMTPUser      string   `mapstructure:"smtp_user" json:"smtp_user,omitempty"`
	From          string   `mapstructure:"from" json:"from,omitempty"`
}

type Rule struct {
	ID       string        `mapstructure:"id" json:"id"`
	Name     string        `mapstructure:"name" json:"name,omitempty"`
	Expr     string        `mapstructure:"expr" json:"expr"`
	For      time.Duration `mapstructure:"for" json:"for"`
	Severity string        `mapstructure:"severity" json:"severity"`
	Channels []string      `mapstructure:"channels" json:"channels"`
	Enabled  *bool         `mapstructure:"enabled" json:"enabled,omitempty"`
	Tags     []string      `mapstructure:"tags" json:"tags,omitempty"`
}

type AutoBan struct {
	Enabled   bool          `mapstructure:"enabled" json:"enabled"`
	Duration  time.Duration `mapstructure:"duration" json:"duration"`
	MaxBans   int           `mapstructure:"max_bans" json:"max_bans"`
	Allowlist []string      `mapstructure:"allowlist" json:"allowlist"`
	RateLimit bool          `mapstructure:"rate_limit" json:"rate_limit"`
}

// Central configures the agent's link to a v1 central server.
type Central struct {
	Addr            string `mapstructure:"addr" json:"addr"`
	EnrollmentToken string `mapstructure:"enrollment_token" json:"-"`
	CAFile          string `mapstructure:"ca_file" json:"ca_file"`
}

// Server configures `serverkeeper server run` (central, v1).
type Server struct {
	GRPCListen     string        `mapstructure:"grpc_listen" json:"grpc_listen"`
	HTTPListen     string        `mapstructure:"http_listen" json:"http_listen"`
	OfflineAfter   time.Duration `mapstructure:"offline_after" json:"offline_after"`
	VM             VM            `mapstructure:"vm" json:"vm"`
	Backup         Backup        `mapstructure:"backup" json:"backup"`
	AuditRetention time.Duration `mapstructure:"audit_retention" json:"audit_retention"`
}

type VM struct {
	URL       string `mapstructure:"url" json:"url"`
	Mode      string `mapstructure:"mode" json:"mode"` // systemd | child
	Binary    string `mapstructure:"binary" json:"binary"`
	Retention string `mapstructure:"retention" json:"retention"`
	DataDir   string `mapstructure:"data_dir" json:"data_dir"`
}

type Backup struct {
	Dest     string `mapstructure:"dest" json:"dest"`
	Schedule string `mapstructure:"schedule" json:"schedule"`
	Keep     int    `mapstructure:"keep" json:"keep"`
}

type Auth struct {
	SessionTTL time.Duration `mapstructure:"session_ttl" json:"session_ttl"`
	OIDC       OIDC          `mapstructure:"oidc" json:"oidc"`
}

type OIDC struct {
	Issuer          string `mapstructure:"issuer" json:"issuer"`
	ClientID        string `mapstructure:"client_id" json:"client_id"`
	ClientSecretEnv string `mapstructure:"client_secret_env" json:"client_secret_env"`
	RedirectURL     string `mapstructure:"redirect_url" json:"redirect_url"`
	AdminGroup      string `mapstructure:"admin_group" json:"admin_group"`
}

type Telemetry struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled"`
	URL     string `mapstructure:"url" json:"url"`
}

func defaults(v *viper.Viper) {
	host, _ := os.Hostname()
	v.SetDefault("server_name", host)
	v.SetDefault("listen", "127.0.0.1:9443")
	v.SetDefault("data_dir", "/var/lib/serverkeeper")
	v.SetDefault("secret_key", "/etc/serverkeeper/secret.key")
	v.SetDefault("privsep", true)
	v.SetDefault("collector.interval", "10s")
	v.SetDefault("collector.retention_raw", "24h")
	v.SetDefault("collector.retention_rollup", "7d")
	v.SetDefault("collector.certs.enabled", true)
	v.SetDefault("web.enabled", true)
	v.SetDefault("collector.certs.probe_ports", []int{443})
	v.SetDefault("collector.certs.interval", "1h")
	v.SetDefault("collector.redis.enabled", "auto")
	v.SetDefault("ssh.config_path", "/etc/ssh/sshd_config")
	v.SetDefault("ssh.rollback_timeout", "120s")
	v.SetDefault("ssh.bruteforce.max_failures", 5)
	v.SetDefault("ssh.bruteforce.window", "10m")
	v.SetDefault("ssh.bruteforce.ban_for", "1h")
	v.SetDefault("ssh.ca.max_ttl", "24h")
	v.SetDefault("ssh.ca.default_ttl", "8h")
	v.SetDefault("harden.schedule", "0 3 * * *")
	v.SetDefault("alerts.repeat_interval", "30m")
	v.SetDefault("alerts.rate_limit", 20)
	v.SetDefault("alerts.auto_ban.duration", "30m")
	v.SetDefault("alerts.auto_ban.max_bans", 50)
	v.SetDefault("server.grpc_listen", "0.0.0.0:9444")
	v.SetDefault("server.http_listen", "127.0.0.1:9443")
	v.SetDefault("server.offline_after", "2m")
	v.SetDefault("server.vm.url", "http://127.0.0.1:8428")
	v.SetDefault("server.vm.mode", "systemd")
	v.SetDefault("server.vm.binary", "/usr/local/bin/victoria-metrics-prod")
	v.SetDefault("server.vm.retention", "90d")
	v.SetDefault("server.vm.data_dir", "/var/lib/serverkeeper/vm")
	v.SetDefault("server.backup.schedule", "30 2 * * *")
	v.SetDefault("server.backup.keep", 7)
	v.SetDefault("server.audit_retention", "8760h")
	v.SetDefault("auth.session_ttl", "12h")
}

// durationHook accepts Go durations plus a "d" (days) suffix such as "7d".
func durationHook(from, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeOf(time.Duration(0)) {
		return data, nil
	}
	switch v := data.(type) {
	case string:
		return ParseDuration(v)
	case int:
		return time.Duration(v) * time.Second, nil
	}
	return data, nil
}

// ParseDuration is time.ParseDuration with "d" and "w" support.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for suf, mul := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if strings.HasSuffix(s, suf) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, suf), 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			return time.Duration(n * float64(mul)), nil
		}
	}
	return time.ParseDuration(s)
}

// Load reads path (missing file = defaults) with SK_* env overrides.
func Load(path string) (*Config, error) {
	v := viper.New()
	defaults(v)
	v.SetEnvPrefix("SK")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if path == "" {
		path = DefaultPath
	}
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil && !os.IsNotExist(err) {
		if _, statErr := os.Stat(path); statErr == nil {
			return nil, fmt.Errorf("config %s: %w (fix the YAML syntax and retry)", path, err)
		}
	}
	var c Config
	hook := mapstructure.ComposeDecodeHookFunc(durationHook, mapstructure.StringToSliceHookFunc(","))
	if err := v.Unmarshal(&c, viper.DecodeHook(hook)); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, c.Validate()
}

// Validate checks ranges and security constraints.
func (c *Config) Validate() error {
	if c.Collector.Interval < time.Second || c.Collector.Interval > 60*time.Second {
		return fmt.Errorf("collector.interval %s out of range: use 1s to 60s", c.Collector.Interval)
	}
	if c.Collector.Certs.Enabled && c.Collector.Certs.Interval < time.Minute {
		return fmt.Errorf("collector.certs.interval %s too short: use at least 1m", c.Collector.Certs.Interval)
	}
	if c.Collector.Redis.Mode() == "" {
		return fmt.Errorf("collector.redis.enabled %q: use auto, true or false", c.Collector.Redis.Enabled)
	}
	for i, in := range c.Collector.Redis.Instances {
		if in.Addr == "" {
			return fmt.Errorf("collector.redis.instances[%d]: addr is required (host:port or unix:/path)", i)
		}
	}
	for _, p := range c.Collector.Certs.ProbePorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("collector.certs.probe_ports: %d is not a port", p)
		}
	}
	if c.SSH.RollbackTimeout < 10*time.Second {
		return fmt.Errorf("ssh.rollback_timeout %s too short: use at least 10s", c.SSH.RollbackTimeout)
	}
	if !IsLoopback(c.Listen) && (c.TLS.Cert == "" || c.TLS.Key == "" || !c.TLS.AllowRemote) {
		return fmt.Errorf("listen %s is not loopback: set tls.cert, tls.key and tls.allow_remote: true, "+
			"or use an SSH tunnel to 127.0.0.1", c.Listen)
	}
	names := map[string]bool{}
	for _, ch := range c.Alerts.Channels {
		if names[ch.Name] {
			return fmt.Errorf("alerts.channels: duplicate name %q", ch.Name)
		}
		names[ch.Name] = true
		switch ch.Type {
		case "slack", "discord", "telegram", "email", "pagerduty", "webhook":
		default:
			return fmt.Errorf("alerts.channels %q: unknown type %q (slack, discord, telegram, email, pagerduty, webhook)",
				ch.Name, ch.Type)
		}
	}
	for _, ig := range c.Harden.Ignore {
		if strings.TrimSpace(ig.Reason) == "" {
			return fmt.Errorf("harden.ignore %s: reason is mandatory", ig.ID)
		}
	}
	return nil
}

// IsLoopback reports whether a listen address binds only to loopback.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Path helpers inside DataDir.
func (c *Config) AgentDB() string   { return c.DataDir + "/agent.db" }
func (c *Config) MetaDB() string    { return c.DataDir + "/serverkeeper.db" }
func (c *Config) BackupDir() string { return c.DataDir + "/backups" }
