// Package notify delivers alerts to Slack, Discord, Telegram, email, PagerDuty and generic webhooks (PRD §8.3).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/secret"
)

type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Alert is one message to deliver.
type Alert struct {
	ID           string    `json:"id"`
	Rule         string    `json:"rule"`
	Server       string    `json:"server"`
	Severity     string    `json:"severity"` // info | warning | critical
	State        string    `json:"state"`    // firing | reminder | resolved | test | summary
	Title        string    `json:"title"`
	Text         string    `json:"text"`
	Fields       []Field   `json:"fields,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	ResolvedAt   time.Time `json:"resolved_at,omitzero"`
	DashboardURL string    `json:"dashboard_url,omitempty"`
	SilenceURL   string    `json:"silence_url,omitempty"`
}

// Notifier is the delivery interface from PRD §9.
type Notifier interface {
	Send(ctx context.Context, a Alert) error
}

// PagerDutyURL is the Events API v2 endpoint (variable for tests).
var PagerDutyURL = "https://events.pagerduty.com/v2/enqueue"

var client = &http.Client{Timeout: 10 * time.Second}

// StatusError is a non-2xx webhook response.
type StatusError struct {
	Channel string
	Code    int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("channel %s: webhook returned HTTP %d (check the URL/token is still valid)", e.Channel, e.Code)
}

// Permanent reports errors that retrying will not fix (4xx except timeout and rate limit).
func Permanent(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != 408 && se.Code != 429
}

// Secret returns the channel secret: env var named by webhook_url_env, else the (sealed) webhook_url.
func Secret(ch config.Channel, box *secret.Box) (string, error) {
	if ch.WebhookURLEnv != "" {
		if v := os.Getenv(ch.WebhookURLEnv); v != "" {
			return v, nil
		}
		if ch.WebhookURL == "" {
			return "", fmt.Errorf("channel %s: env %s is empty: set it in the agent environment "+
				"(systemd EnvironmentFile) and restart", ch.Name, ch.WebhookURLEnv)
		}
	}
	if ch.WebhookURL == "" {
		return "", fmt.Errorf("channel %s: no webhook_url or webhook_url_env configured: "+
			"add one with `serverkeeper alert channels add`", ch.Name)
	}
	if !secret.IsSealed(ch.WebhookURL) {
		return ch.WebhookURL, nil
	}
	if box == nil {
		return "", fmt.Errorf("channel %s: secret key not loaded, cannot decrypt webhook_url", ch.Name)
	}
	v, err := box.Open(ch.WebhookURL)
	if err != nil {
		return "", fmt.Errorf("channel %s: %w", ch.Name, err)
	}
	return v, nil
}

// New builds a notifier for a configured channel; secrets are resolved from env or decrypted with box.
func New(ch config.Channel, box *secret.Box) (Notifier, error) {
	if ch.Type == "email" {
		return newEmail(ch, box)
	}
	sec, err := Secret(ch, box)
	if err != nil {
		return nil, err
	}
	h := &hook{name: ch.Name, url: sec}
	switch ch.Type {
	case "slack":
		h.body = slackBody
	case "discord":
		h.body = discordBody
	case "webhook":
		h.body = webhookBody
	case "telegram":
		if ch.ChatID == "" {
			return nil, fmt.Errorf("channel %s: telegram needs chat_id", ch.Name)
		}
		h.url = strings.TrimRight(sec, "/") + "/sendMessage"
		h.body = func(a Alert) any { return telegramBody(ch.ChatID, a) }
	case "pagerduty":
		h.url = PagerDutyURL
		h.body = func(a Alert) any { return pagerdutyBody(sec, a) }
	default:
		return nil, fmt.Errorf("channel %s: unknown type %q (slack, discord, telegram, email, pagerduty, webhook)",
			ch.Name, ch.Type)
	}
	return h, nil
}

type hook struct {
	name string
	url  string
	body func(Alert) any
}

func (h *hook) Send(ctx context.Context, a Alert) error { return post(ctx, h.name, h.url, h.body(a)) }

// post sends JSON; errors never contain the URL (AL-8).
func post(ctx context.Context, name, u string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("channel %s: invalid webhook URL", name)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("channel %s: %s (check network access to the webhook)", name, secret.Redact(err.Error()))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return &StatusError{Channel: name, Code: resp.StatusCode}
	}
	return nil
}

// ---- shared text format (PRD §8.3 example) ----

var icons = map[string]string{"critical": "🔴", "warning": "🟠", "info": "🔵"}

var colors = map[string]int{"critical": 0xd32f2f, "warning": 0xf9a825, "info": 0x1e88e5, "resolved": 0x2e7d32}

func color(a Alert) int {
	if a.State == "resolved" {
		return colors["resolved"]
	}
	if c, ok := colors[a.Severity]; ok {
		return c
	}
	return colors["info"]
}

// Header is e.g. "🔴 CRITICAL · web-01 · RAM almost full".
func Header(a Alert) string {
	icon, sev := icons[a.Severity], strings.ToUpper(a.Severity)
	if icon == "" {
		icon = "🔵"
	}
	switch a.State {
	case "resolved":
		icon, sev = "✅", "RESOLVED"
	case "test":
		icon, sev = "🧪", "TEST"
	}
	h := icon + " " + sev + " · " + a.Server + " · " + a.Title
	if a.State == "reminder" {
		h += " (still firing)"
	}
	return h
}

// Body is the alert text plus one "Name: value" line per field.
func Body(a Alert) string {
	var b strings.Builder
	b.WriteString(a.Text)
	for _, f := range a.Fields {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(f.Name + ": " + f.Value)
	}
	return b.String()
}

// Footer is e.g. "Firing since 23:41 WIB · Rule: mem_available_low" in the host's local timezone.
func Footer(a Alert) string {
	switch a.State {
	case "test":
		return "Sent " + clock(a.StartedAt) + " · Test message"
	case "resolved":
		end := a.ResolvedAt
		if end.IsZero() {
			end = time.Now()
		}
		return "Resolved " + clock(end) + " · Firing since " + clock(a.StartedAt) + " · Rule: " + a.Rule
	}
	return "Firing since " + clock(a.StartedAt) + " · Rule: " + a.Rule
}

func clock(t time.Time) string {
	t, n := t.Local(), time.Now()
	if t.YearDay() != n.YearDay() || t.Year() != n.Year() {
		return t.Format("Jan 2 15:04 MST")
	}
	return t.Format("15:04 MST")
}

// Text is the full plain-text message (header, body, footer, links).
func Text(a Alert) string {
	s := Header(a)
	if b := Body(a); b != "" {
		s += "\n" + b
	}
	s += "\n" + Footer(a)
	for _, l := range links(a) {
		s += "\n" + l[0] + ": " + l[1]
	}
	return s
}

// links returns the action buttons: [label, url].
func links(a Alert) [][2]string {
	var out [][2]string
	if a.DashboardURL != "" {
		out = append(out, [2]string{"Open dashboard", a.DashboardURL})
	}
	if a.SilenceURL != "" && a.State != "resolved" && a.State != "test" {
		out = append(out, [2]string{"Silence 1h", a.SilenceURL})
	}
	return out
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
