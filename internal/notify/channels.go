package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/secret"
)

type obj = map[string]any

var slackEsc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// slackBody is a Block Kit message inside a coloured attachment.
func slackBody(a Alert) any {
	text := "*" + slackEsc.Replace(Header(a)) + "*"
	if b := Body(a); b != "" {
		text += "\n" + slackEsc.Replace(b)
	}
	blocks := []any{
		obj{"type": "section", "text": obj{"type": "mrkdwn", "text": trunc(text, 3000)}},
		obj{"type": "context", "elements": []any{obj{"type": "mrkdwn", "text": slackEsc.Replace(Footer(a))}}},
	}
	var btns []any
	for _, l := range links(a) {
		btns = append(btns, obj{"type": "button", "text": obj{"type": "plain_text", "text": l[0]}, "url": l[1]})
	}
	if len(btns) > 0 {
		blocks = append(blocks, obj{"type": "actions", "elements": btns})
	}
	return obj{"text": Header(a), "attachments": []any{obj{"color": fmt.Sprintf("#%06x", color(a)), "blocks": blocks}}}
}

// discordBody is one embed; actions are markdown links.
func discordBody(a Alert) any {
	desc := Body(a)
	var ls []string
	for _, l := range links(a) {
		ls = append(ls, "["+l[0]+"]("+l[1]+")")
	}
	if len(ls) > 0 {
		desc += "\n\n" + strings.Join(ls, " · ")
	}
	return obj{"embeds": []any{obj{
		"title":       trunc(Header(a), 256),
		"description": trunc(desc, 4096),
		"color":       color(a),
		"footer":      obj{"text": trunc(Footer(a), 2048)},
		"timestamp":   a.StartedAt.UTC().Format(time.RFC3339),
	}}}
}

func telegramBody(chatID string, a Alert) any {
	text := "<b>" + html.EscapeString(Header(a)) + "</b>"
	if b := Body(a); b != "" {
		text += "\n" + html.EscapeString(b)
	}
	text += "\n<i>" + html.EscapeString(Footer(a)) + "</i>"
	for _, l := range links(a) {
		text += "\n<a href=\"" + html.EscapeString(l[1]) + "\">" + l[0] + "</a>"
	}
	return obj{"chat_id": chatID, "text": trunc(text, 4096), "parse_mode": "HTML", "disable_web_page_preview": true}
}

// pagerdutyBody is an Events API v2 trigger/resolve; dedup_key is the alert id.
func pagerdutyBody(key string, a Alert) any {
	if a.State == "resolved" {
		return obj{"routing_key": key, "event_action": "resolve", "dedup_key": a.ID}
	}
	sev := a.Severity
	if sev != "critical" && sev != "warning" {
		sev = "info"
	}
	details := obj{"text": a.Text, "rule": a.Rule, "state": a.State}
	for _, f := range a.Fields {
		details[f.Name] = f.Value
	}
	m := obj{"routing_key": key, "event_action": "trigger", "dedup_key": a.ID, "payload": obj{
		"summary": trunc(Header(a), 1024), "source": a.Server, "severity": sev,
		"timestamp": a.StartedAt.UTC().Format(time.RFC3339), "custom_details": details,
	}}
	var ls []any
	for _, l := range links(a) {
		ls = append(ls, obj{"href": l[1], "text": l[0]})
	}
	if len(ls) > 0 {
		m["links"] = ls
	}
	return m
}

func webhookBody(a Alert) any {
	return struct {
		Alert
		Message string `json:"message"`
	}{a, Text(a)}
}

// ---- email (net/smtp with STARTTLS) ----

type email struct {
	ch config.Channel
	pw string
}

func newEmail(ch config.Channel, box *secret.Box) (Notifier, error) {
	if ch.SMTPAddr == "" || ch.From == "" || len(ch.To) == 0 {
		return nil, fmt.Errorf("channel %s: email needs smtp_addr, from and to", ch.Name)
	}
	if _, _, err := net.SplitHostPort(ch.SMTPAddr); err != nil {
		return nil, fmt.Errorf("channel %s: smtp_addr %q must be host:port (e.g. smtp.example.com:587)", ch.Name, ch.SMTPAddr)
	}
	m := &email{ch: ch}
	if ch.SMTPUser != "" {
		pw, err := Secret(ch, box)
		if err != nil {
			return nil, err
		}
		m.pw = pw
	}
	return m, nil
}

var hdrClean = strings.NewReplacer("\r", " ", "\n", " ")

func (m *email) Send(ctx context.Context, a Alert) error {
	err := m.send(ctx, a)
	if err != nil {
		return fmt.Errorf("channel %s: smtp: %s", m.ch.Name, secret.Redact(err.Error()))
	}
	return nil
}

func (m *email) send(ctx context.Context, a Alert) error {
	host, _, _ := net.SplitHostPort(m.ch.SMTPAddr)
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", m.ch.SMTPAddr)
	if err != nil {
		return err
	}
	dl := time.Now().Add(30 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(dl) {
		dl = t
	}
	_ = conn.SetDeadline(dl)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("%s does not offer STARTTLS: refusing to send in clear text", m.ch.SMTPAddr)
	}
	if m.ch.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", m.ch.SMTPUser, m.pw, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.ch.From); err != nil {
		return err
	}
	for _, to := range m.ch.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + hdrClean.Replace(m.ch.From) + "\r\n" +
		"To: " + hdrClean.Replace(strings.Join(m.ch.To, ", ")) + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", hdrClean.Replace(Header(a))) + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(Text(a), "\n", "\r\n") + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
