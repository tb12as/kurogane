package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/secret"
)

func sample() Alert {
	return Alert{ID: "e1", Rule: "mem_available_low", Server: "web-01", Severity: "critical", State: "firing",
		Title: "RAM almost full", Text: "Available memory 4.2% (168 MB of 4 GB) for 6 min",
		Fields:       []Field{{"Top processes", "java 2.1 GB, mysqld 1.2 GB, node 310 MB"}},
		StartedAt:    time.Now(),
		DashboardURL: "https://sk.example/alerts?event=e1", SilenceURL: "https://sk.example/alerts/silence?rule=x&for=1h"}
}

// capture starts a server recording the last JSON body and request path.
func capture(t *testing.T, code int) (*httptest.Server, *map[string]any, *string) {
	var body map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		body = nil
		if err := json.Unmarshal(b, &body); err != nil {
			t.Errorf("bad json: %s", b)
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &path
}

func TestText(t *testing.T) {
	a := sample()
	txt := Text(a)
	want := "🔴 CRITICAL · web-01 · RAM almost full\nAvailable memory 4.2% (168 MB of 4 GB) for 6 min\n" +
		"Top processes: java 2.1 GB, mysqld 1.2 GB, node 310 MB\nFiring since " +
		a.StartedAt.Local().Format("15:04 MST") + " · Rule: mem_available_low"
	if !strings.HasPrefix(txt, want) {
		t.Fatalf("got\n%s\nwant prefix\n%s", txt, want)
	}
	a.State = "resolved"
	if h := Header(a); !strings.HasPrefix(h, "✅ RESOLVED · web-01") {
		t.Fatal(h)
	}
}

func TestSlack(t *testing.T) {
	srv, body, _ := capture(t, 200)
	n, err := New(config.Channel{Name: "ops", Type: "slack", WebhookURL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	att := (*body)["attachments"].([]any)[0].(map[string]any)
	if att["color"] != "#d32f2f" {
		t.Fatal(att["color"])
	}
	blocks := att["blocks"].([]any)
	if len(blocks) != 3 || blocks[2].(map[string]any)["type"] != "actions" {
		t.Fatalf("%v", blocks)
	}
	btns := blocks[2].(map[string]any)["elements"].([]any)
	if btns[1].(map[string]any)["text"].(map[string]any)["text"] != "Silence 1h" {
		t.Fatal(btns)
	}
	if !strings.Contains(blocks[0].(map[string]any)["text"].(map[string]any)["text"].(string), "*🔴 CRITICAL · web-01") {
		t.Fatal(blocks[0])
	}
}

func TestDiscord(t *testing.T) {
	srv, body, _ := capture(t, 204)
	n, _ := New(config.Channel{Name: "phone", Type: "discord", WebhookURL: srv.URL}, nil)
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	em := (*body)["embeds"].([]any)[0].(map[string]any)
	if em["color"].(float64) != 0xd32f2f || !strings.Contains(em["description"].(string), "[Silence 1h](https://") {
		t.Fatal(em)
	}
}

func TestTelegramPagerDutyWebhook(t *testing.T) {
	srv, body, path := capture(t, 200)
	n, err := New(config.Channel{Name: "tg", Type: "telegram", WebhookURL: srv.URL + "/bot123:abc", ChatID: "-100"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if *path != "/bot123:abc/sendMessage" || (*body)["chat_id"] != "-100" || (*body)["parse_mode"] != "HTML" {
		t.Fatal(*path, *body)
	}

	PagerDutyURL = srv.URL + "/v2/enqueue"
	t.Setenv("KRGN_PD", "rk-1")
	n, _ = New(config.Channel{Name: "pd", Type: "pagerduty", WebhookURLEnv: "KRGN_PD"}, nil)
	a := sample()
	_ = n.Send(context.Background(), a)
	if (*body)["routing_key"] != "rk-1" || (*body)["event_action"] != "trigger" || (*body)["dedup_key"] != "e1" {
		t.Fatal(*body)
	}
	a.State = "resolved"
	_ = n.Send(context.Background(), a)
	if (*body)["event_action"] != "resolve" || (*body)["dedup_key"] != "e1" {
		t.Fatal(*body)
	}

	n, _ = New(config.Channel{Name: "wh", Type: "webhook", WebhookURL: srv.URL}, nil)
	_ = n.Send(context.Background(), sample())
	if (*body)["id"] != "e1" || !strings.HasPrefix((*body)["message"].(string), "🔴 CRITICAL") {
		t.Fatal(*body)
	}
}

func TestSecretsAndErrors(t *testing.T) {
	box, _ := secret.New(strings.Repeat("ab", 32))
	srv, _, _ := capture(t, 404)
	sealed, _ := box.Seal(srv.URL)
	n, err := New(config.Channel{Name: "ops", Type: "slack", WebhookURL: sealed}, box)
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), sample())
	if !Permanent(err) || strings.Contains(err.Error(), srv.URL) {
		t.Fatal(err)
	}
	if _, err := New(config.Channel{Name: "ops", Type: "slack", WebhookURL: sealed}, nil); err == nil {
		t.Fatal("sealed without box must fail")
	}
	if _, err := New(config.Channel{Name: "ops", Type: "slack", WebhookURLEnv: "KRGN_NOPE_UNSET"}, nil); err == nil {
		t.Fatal("empty env must fail")
	}
	// transport errors must not leak the token in the URL
	n, _ = New(config.Channel{Name: "tg", Type: "telegram", WebhookURL: "http://127.0.0.1:1/botSECRET123", ChatID: "1"}, nil)
	err = n.Send(context.Background(), sample())
	if err == nil || strings.Contains(err.Error(), "SECRET123") || Permanent(err) {
		t.Fatal(err)
	}
}

func TestEmail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { c.Write([]byte(s + "\r\n")) }
		say("220 fake")
		var data strings.Builder
		inData := false
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if l == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 ok")
					continue
				}
				data.WriteString(l)
				continue
			}
			switch strings.ToUpper(strings.Fields(l)[0]) {
			case "EHLO":
				say("250 fake")
			case "DATA":
				inData = true
				say("354 go")
			case "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	n, err := New(config.Channel{Name: "mail", Type: "email", SMTPAddr: ln.Addr().String(), From: "sk@x", To: []string{"ops@x"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	if !strings.Contains(msg, "Subject: =?utf-8?q?") || !strings.Contains(msg, "Rule: mem_available_low") {
		t.Fatal(msg)
	}
}

func TestSummaryRendering(t *testing.T) {
	a := sample()
	a.State, a.ID, a.Rule, a.Title = "summary", "summary", "summary", "Alert summary today"
	a.Text = "Total: 3\nOpen: 2\nNoise: 1"
	if !strings.HasPrefix(Header(a), "SUMMARY") || !strings.HasPrefix(Footer(a), "Generated ") ||
		strings.Contains(Text(a), "Silence 1h") || !strings.Contains(Text(a), "Open dashboard") {
		t.Fatal(Text(a))
	}
	for name, body := range map[string]any{
		"slack": slackBody(a), "discord": discordBody(a), "telegram": telegramBody("chat", a),
		"webhook": webhookBody(a),
	} {
		raw, err := json.Marshal(body)
		if err != nil || strings.Contains(string(raw), "Silence 1h") || !strings.Contains(string(raw), "SUMMARY") ||
			!strings.Contains(string(raw), "Total: 3") {
			t.Fatalf("%s: %s, %v", name, raw, err)
		}
	}
}
