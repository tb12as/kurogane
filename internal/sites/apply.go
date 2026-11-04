package sites

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/webconf"
)

// Errors the API maps to status codes.
var (
	ErrNotFound = errors.New("site not found: run `serverkeeper sites list` for ids and names")
	ErrRefused  = errors.New("refused")
	ErrBusy     = errors.New("another site change is in progress: retry in a few seconds")
)

// Probe settings: after a reload, a site that answered before is retried this many times before rollback.
var (
	ProbeRetries = 3
	ProbeSpacing = time.Second
)

const (
	pendingBucket = "sites_pending"
	pendingKey    = "current"
)

// FileOp is one file move; Undo reverses it.
type FileOp struct {
	Op   string `json:"op"` // link | unlink | rename
	From string `json:"from,omitempty"`
	To   string `json:"to"`
}

func (o FileOp) String() string {
	switch o.Op {
	case "link":
		return "link " + o.To + " -> " + o.From
	case "unlink":
		return "unlink " + o.To
	}
	return "rename " + o.From + " -> " + o.To
}

// Undo returns the operation that reverses o.
func (o FileOp) Undo() FileOp {
	switch o.Op {
	case "link":
		return FileOp{Op: "unlink", From: o.From, To: o.To}
	case "unlink":
		return FileOp{Op: "link", From: o.From, To: o.To}
	}
	return FileOp{Op: "rename", From: o.To, To: o.From}
}

// Plan is the dry run of an enable or disable.
type Plan struct {
	Site     Site     `json:"site"`
	Action   string   `json:"action"` // enable | disable
	Ops      []FileOp `json:"ops"`
	Diff     string   `json:"diff"`
	Affected []Site   `json:"affected"` // every site in the file
	Impact   []string `json:"impact"`
	Warnings []string `json:"warnings"`
}

// pending is persisted while a change is applied so a restart halfway can undo it.
type pending struct {
	Change db.SiteChange `json:"change"`
	Undo   []FileOp      `json:"undo"`
	Unit   string        `json:"unit"`
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// Plan computes what enabling (enable=true) or disabling the site would do, without touching the host.
func (m *Manager) Plan(_ context.Context, id string, enable bool) (*Plan, error) {
	inv := m.Inventory()
	s, ok := inv.Site(id)
	if !ok {
		return nil, ErrNotFound
	}
	action := map[bool]string{true: "enable", false: "disable"}[enable]
	switch {
	case s.Enabled == enable:
		return nil, refuse("%s is already %sd", s.Name, action)
	case s.Toggle == "":
		return nil, refuse("%s cannot be toggled: %s", s.Name, s.NoToggle)
	}
	p := &Plan{Site: s, Action: action, Warnings: []string{}}
	for _, x := range inv.Sites {
		if x.Kind == s.Kind && x.File == s.File {
			p.Affected = append(p.Affected, x)
		}
	}
	switch {
	case s.Toggle == ToggleLink && enable:
		p.Ops = []FileOp{{Op: "link", From: s.Available, To: enabledDir(s.Available) + "/" + path.Base(s.Available)}}
	case s.Toggle == ToggleLink:
		p.Ops = []FileOp{{Op: "unlink", From: s.Available, To: s.File}}
	case enable:
		p.Ops = []FileOp{{Op: "rename", From: s.File, To: strings.TrimSuffix(s.File, DisabledSuffix)}}
	default:
		p.Ops = []FileOp{{Op: "rename", From: s.File, To: s.File + DisabledSuffix}}
	}
	for _, o := range p.Ops {
		switch o.Op {
		case "link":
			p.Diff += "+ " + o.To + " -> ../" + path.Base(path.Dir(o.From)) + "/" + path.Base(o.From) + "\n"
		case "unlink":
			p.Diff += "- " + o.To + " -> " + o.From + "\n"
		default:
			p.Diff += "- " + o.From + "\n+ " + o.To + "\n"
		}
	}
	m.impact(p, inv)
	return p, nil
}

// enabledDir maps a sites-available file to its sites-enabled directory.
func enabledDir(available string) string {
	for _, l := range layouts {
		if l.method == ToggleLink && l.available == path.Dir(available) {
			return l.enabled
		}
	}
	return ""
}

func (m *Manager) impact(p *Plan, inv Inventory) {
	w, _ := inv.Server(p.Site.Kind)
	verb := map[string]string{"enable": "Starts serving", "disable": "Stops serving"}[p.Action]
	for _, a := range p.Affected {
		p.Impact = append(p.Impact, fmt.Sprintf("%s %s on %s.", verb, strings.Join(nonEmpty(a.Names, a.Name), ", "),
			ports(a.Listen)))
	}
	p.Impact = append(p.Impact, fmt.Sprintf("Checked with `%s` before `systemctl reload %s`; undone automatically if "+
		"the check or the reload fails, or if a site that answered before stops answering.", testCmd(p.Site.Kind), w.Unit))
	if len(p.Affected) > 1 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s holds %d sites; all of them are %sd together.", p.Site.File,
			len(p.Affected), p.Action))
	}
	if !w.ConfigOK && !w.TestedAt.IsZero() {
		p.Warnings = append(p.Warnings, "The current configuration already fails `"+testCmd(w.Kind)+"` ("+w.ConfigError+
			"): the change will be refused until that is fixed.")
	}
	if p.Action == "disable" {
		for _, a := range p.Affected {
			if a.Default {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s is the default site on %s: requests for unknown names "+
					"will go to another site there.", a.Name, ports(a.Listen)))
			}
			for _, u := range a.Upstreams {
				if m.d.SelfPort != "" && strings.Contains(u, ":"+m.d.SelfPort) {
					p.Warnings = append(p.Warnings, fmt.Sprintf("%s proxies to ServerKeeper itself (%s): disabling it "+
						"cuts access to this dashboard through it. Keep an SSH tunnel open.", a.Name, u))
				}
			}
		}
		for _, port := range orphanPorts(p.Affected, inv) {
			p.Warnings = append(p.Warnings, fmt.Sprintf("No other %s site listens on port %d: %s stops accepting "+
				"connections there.", p.Site.Kind, port, p.Site.Kind))
		}
		return
	}
	for _, a := range p.Affected {
		if a.CertDays != nil && *a.CertDays < 14 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("The certificate of %s expires in %.1f days.", a.Name, *a.CertDays))
		}
		for _, x := range inv.Sites {
			if n := overlap(x, a); x.Enabled && x.Kind == a.Kind && x.File != a.File && n != "" {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s is already served by another enabled site (%s:%d) on "+
					"the same port: the server keeps using the first definition it reads.", n, x.File, x.Line))
			}
		}
	}
}

func nonEmpty(names []string, fallback string) []string {
	if len(names) == 0 {
		return []string{fallback}
	}
	return names
}

func ports(ls []webconf.Listen) string {
	var ps []string
	for _, l := range ls {
		p := strconv.Itoa(l.Port)
		if l.TLS {
			p += " (TLS)"
		}
		if !slices.Contains(ps, p) {
			ps = append(ps, p)
		}
	}
	return "port " + strings.Join(ps, ", ")
}

// orphanPorts lists ports of the affected sites that no other enabled site of the same server listens on.
func orphanPorts(affected []Site, inv Inventory) []int {
	gone := map[string]bool{}
	for _, a := range affected {
		gone[a.ID] = true
	}
	var out []int
	for _, a := range affected {
		for _, l := range a.Listen {
			used := false
			for _, x := range inv.Sites {
				if x.Enabled && x.Kind == a.Kind && !gone[x.ID] && slices.ContainsFunc(x.Listen, func(y webconf.Listen) bool {
					return y.Port == l.Port
				}) {
					used = true
					break
				}
			}
			if !used && !slices.Contains(out, l.Port) {
				out = append(out, l.Port)
			}
		}
	}
	sort.Ints(out)
	return out
}

// overlap returns a name two sites share on a common port, or "".
func overlap(a, b Site) string {
	port := false
	for _, x := range a.Listen {
		for _, y := range b.Listen {
			port = port || x.Port == y.Port
		}
	}
	if !port {
		return ""
	}
	for _, n := range a.Names {
		if n != "_" && n != "" && slices.ContainsFunc(b.Names, func(m string) bool { return strings.EqualFold(n, m) }) {
			return n
		}
	}
	return ""
}

// Apply enables or disables a site: config test before and after the file move, reload, then probes of every
// site that answered before. Any failure undoes the move and reloads again.
func (m *Manager) Apply(ctx context.Context, id string, enable bool) (db.SiteChange, error) {
	if !m.applyMu.TryLock() {
		return db.SiteChange{}, ErrBusy
	}
	defer m.applyMu.Unlock()
	p, err := m.Plan(ctx, id, enable)
	if err != nil {
		return db.SiteChange{}, err
	}
	w, _ := m.Inventory().Server(p.Site.Kind)
	if ok, msg := configTest(ctx, m.d.Ex, w.Kind); !ok {
		return db.SiteChange{}, refuse("the current configuration already fails `%s`: %s. Fix it first (nothing was "+
			"changed)", testCmd(w.Kind), msg)
	}
	var opsText []string
	for _, o := range p.Ops {
		opsText = append(opsText, o.String())
	}
	ch := db.SiteChange{ID: db.NewID(), Actor: audit.From(ctx).Actor, SiteID: p.Site.ID, SiteName: p.Site.Name,
		Kind: p.Site.Kind, Action: p.Action, Ops: strings.Join(opsText, "; "), Status: "applying", TS: m.d.Now()}

	// baseline: sites of this server that answer now and should still answer afterwards
	affected := map[string]bool{}
	for _, a := range p.Affected {
		affected[a.ID] = true
	}
	var cand, watch []Site
	for _, s := range m.Inventory().Sites {
		if s.Kind == p.Site.Kind && s.Enabled && !affected[s.ID] {
			cand = append(cand, s)
		}
	}
	for i, ok := range m.probeAll(ctx, cand, 1) {
		if ok {
			watch = append(watch, cand[i])
		}
	}

	pd := pending{Change: ch, Unit: w.Unit}
	for i := len(p.Ops) - 1; i >= 0; i-- {
		pd.Undo = append(pd.Undo, p.Ops[i].Undo())
	}
	m.savePending(&pd)
	fail := func(status, msg string, reload bool) (db.SiteChange, error) {
		m.undo(ctx, pd.Undo)
		if reload {
			m.reload(ctx, w.Unit)
		}
		ch.Status, ch.Error = status, msg
		m.finish(ctx, ch, p)
		if status == "rolled_back" && m.d.Fire != nil {
			m.d.Fire(ctx, alert.Event{Rule: "site_change_rolled_back", Severity: "critical", Once: true,
				Title:  fmt.Sprintf("%s of %s rolled back", strings.ToUpper(p.Action[:1])+p.Action[1:], p.Site.Name),
				Text:   msg + " The previous configuration was restored and " + w.Unit + " reloaded.",
				Labels: map[string]string{"site": p.Site.Name}, Fields: map[string]string{"Change": ch.Ops}})
		}
		return ch, fmt.Errorf("%s", msg)
	}

	for i, o := range p.Ops {
		if err := m.do(o); err != nil {
			pd.Undo = pd.Undo[len(p.Ops)-i:] // undo only what was done
			return fail("failed", fmt.Sprintf("%s: %v (nothing was reloaded)", o, err), false)
		}
	}
	if ok, msg := configTest(ctx, m.d.Ex, w.Kind); !ok {
		return fail("failed", fmt.Sprintf("`%s` rejected the change: %s. The file move was undone; nothing was "+
			"reloaded.", testCmd(w.Kind), msg), false)
	}
	if err := m.reload(ctx, w.Unit); err != nil {
		return fail("rolled_back", fmt.Sprintf("systemctl reload %s failed: %s.", w.Unit, errText(err)), true)
	}
	if _, err := m.d.Ex.Run(ctx, "systemctl", "is-active", "--quiet", w.Unit); err != nil {
		return fail("rolled_back", w.Unit+" is not active after the reload.", true)
	}
	if lost := m.lost(ctx, watch); len(lost) > 0 {
		return fail("rolled_back", fmt.Sprintf("%s stopped answering after the reload.", strings.Join(lost, ", ")), true)
	}
	ch.Status = "applied"
	m.finish(ctx, ch, p)
	return ch, nil
}

// lost returns the names of watched sites that no longer answer after a few retries.
func (m *Manager) lost(ctx context.Context, watch []Site) []string {
	var out []string
	for i, ok := range m.probeAll(ctx, watch, ProbeRetries) {
		if !ok {
			out = append(out, watch[i].Name)
		}
	}
	return out
}

// probeAll probes sites concurrently (at most 8 at a time), trying each up to tries times.
func (m *Manager) probeAll(ctx context.Context, list []Site, tries int) []bool {
	out := make([]bool, len(list))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, s := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			for t := 0; t < tries && !out[i]; t++ {
				if t > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(ProbeSpacing):
					}
				}
				out[i] = m.probe(ctx, s)
			}
		}()
	}
	wg.Wait()
	return out
}

// errText is a command's stderr when there is one, else the error.
func errText(err error) string {
	var re *executor.RunError
	if errors.As(err, &re) && re.Stderr != "" {
		return re.Stderr
	}
	return err.Error()
}

func (m *Manager) do(o FileOp) error {
	switch o.Op {
	case "link":
		return m.d.Ex.LinkSite(o.From, o.To)
	case "unlink":
		return m.d.Ex.UnlinkSite(o.To)
	}
	return m.d.Ex.RenameSite(o.From, o.To)
}

func (m *Manager) undo(_ context.Context, ops []FileOp) {
	for _, o := range ops {
		if err := m.do(o); err != nil {
			slog.Error("site change undo failed: restore by hand", "op", o.String(), "err", err)
		}
	}
}

func (m *Manager) reload(ctx context.Context, unit string) error {
	_, err := m.d.Ex.Run(ctx, "systemctl", "reload", unit)
	return err
}

// finish records the change, clears the pending marker and rescans.
func (m *Manager) finish(ctx context.Context, ch db.SiteChange, p *Plan) {
	m.clearPending()
	if m.d.DB != nil {
		if err := m.d.DB.SaveSiteChange(context.WithoutCancel(ctx), ch); err != nil {
			slog.Error("save site change", "err", err)
		}
	}
	if m.d.Audit != nil {
		m.d.Audit.Record(ctx, "web.site."+p.Action, p.Site.ID, map[string]any{"enabled": p.Site.Enabled},
			map[string]any{"status": ch.Status, "ops": ch.Ops, "error": ch.Error})
	}
	m.Scan(ctx, true)
	if m.d.Publish != nil {
		m.d.Publish("site_change", ch)
	}
}

func (m *Manager) savePending(p *pending) {
	if m.d.Store == nil {
		return
	}
	if err := m.d.Store.Put(pendingBucket, pendingKey, p); err != nil {
		slog.Error("save pending site change", "err", err)
	}
}

func (m *Manager) clearPending() {
	if m.d.Store != nil {
		_ = m.d.Store.Delete(pendingBucket, pendingKey)
	}
}

// resume undoes a change the agent was applying when it stopped.
func (m *Manager) resume(ctx context.Context) {
	if m.d.Store == nil {
		return
	}
	var p pending
	if err := m.d.Store.Get(pendingBucket, pendingKey, &p); err != nil || p.Change.ID == "" {
		return
	}
	slog.Warn("undoing a site change interrupted by an agent restart", "site", p.Change.SiteName)
	m.undo(ctx, p.Undo)
	_ = m.reload(ctx, p.Unit)
	p.Change.Status, p.Change.Error = "rolled_back", "the agent stopped while applying the change; it was undone on restart."
	m.clearPending()
	if m.d.DB != nil {
		_ = m.d.DB.SaveSiteChange(ctx, p.Change)
	}
	if m.d.Fire != nil {
		m.d.Fire(ctx, alert.Event{Rule: "site_change_rolled_back", Severity: "critical", Once: true,
			Title: "Site change of " + p.Change.SiteName + " rolled back", Text: p.Change.Error,
			Labels: map[string]string{"site": p.Change.SiteName}})
	}
}

// Changes lists the site change history.
func (m *Manager) Changes(ctx context.Context) ([]db.SiteChange, error) {
	if m.d.DB == nil {
		return []db.SiteChange{}, nil
	}
	return m.d.DB.ListSiteChanges(ctx, 100)
}

// Reload runs the config test and reloads the web server of kind; a failing test refuses the reload, so a
// broken file never takes the running server down.
func (m *Manager) Reload(ctx context.Context, kind string) error {
	w, ok := m.Inventory().Server(kind)
	if !ok {
		return ErrNotFound
	}
	if ok, msg := configTest(ctx, m.d.Ex, kind); !ok {
		return refuse("`%s` fails: %s. Not reloading: the reload would fail", testCmd(kind), msg)
	}
	err := m.reload(ctx, w.Unit)
	if m.d.Audit != nil {
		after := map[string]any{"ok": err == nil}
		if err != nil {
			after["error"] = errText(err)
		}
		m.d.Audit.Record(ctx, "web.reload", w.Unit, nil, after)
	}
	if err != nil {
		return fmt.Errorf("systemctl reload %s failed: %s", w.Unit, errText(err))
	}
	m.Scan(ctx, true)
	return nil
}

// Config returns the file that defines a site and its content (the sites-available file for a link).
func (m *Manager) Config(_ context.Context, id string) (string, string, error) {
	s, ok := m.Inventory().Site(id)
	if !ok {
		return "", "", ErrNotFound
	}
	f := s.File
	if s.Available != "" {
		f = s.Available
	}
	b, err := m.d.Ex.ReadFile(f)
	if err != nil {
		return f, "", err
	}
	return f, string(b), nil
}
