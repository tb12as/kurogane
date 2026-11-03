package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Hub fans out live events to SSE clients (GET /api/v1/stream).
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

// Publish sends an SSE event to all subscribers; slow clients drop messages instead of blocking.
func (h *Hub) Publish(event string, v any) {
	if h == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", event, b))
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subs {
		select {
		case c <- msg:
		default:
		}
	}
}

func (h *Hub) serve(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	c := make(chan []byte, 32)
	h.mu.Lock()
	h.subs[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.subs, c)
		h.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case m := <-c:
			w.Write(m)
			fl.Flush()
		case <-t.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}
