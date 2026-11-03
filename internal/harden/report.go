package harden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/harden/checks"
)

// Report is the exported scan (HD-4).
type Report struct {
	Server    string          `json:"server"`
	ScanID    string          `json:"scan_id"`
	StartedAt time.Time       `json:"started_at"`
	Score     float64         `json:"score"`
	Grade     string          `json:"grade"`
	Counts    map[string]int  `json:"counts"`
	Results   []checks.Result `json:"results"`
}

func newReport(server string, sc db.Scan) Report {
	r := Report{Server: server, ScanID: sc.ID, StartedAt: sc.StartedAt, Score: sc.Score, Grade: sc.Grade,
		Counts: map[string]int{}, Results: Results(sc)}
	for _, x := range r.Results {
		r.Counts[x.Status]++
	}
	return r
}

// failed returns failing checks, most severe first.
func (r Report) failed() []checks.Result {
	var out []checks.Result
	for _, x := range r.Results {
		if x.Status == checks.Fail {
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return checks.Rank(out[i].Severity) > checks.Rank(out[j].Severity) })
	return out
}

// Render exports a scan as json, md or pdf; it returns the body, content type and file extension.
func (s *Service) Render(sc db.Scan, format string) ([]byte, string, error) {
	return Render(s.cfg.ServerName, sc, format)
}

// Render exports a scan as json, md or pdf.
func Render(server string, sc db.Scan, format string) ([]byte, string, error) {
	r := newReport(server, sc)
	switch format {
	case "", "json":
		b, err := json.MarshalIndent(r, "", "  ")
		return b, "application/json", err
	case "md", "markdown":
		return []byte(r.markdown()), "text/markdown; charset=utf-8", nil
	case "pdf":
		b, err := r.pdf()
		return b, "application/pdf", err
	}
	return nil, "", fmt.Errorf("unknown report format %q: use json, md or pdf", format)
}

func (r Report) summary() string {
	return fmt.Sprintf("%d pass, %d fail, %d n/a, %d ignored, %d error", r.Counts[checks.Pass], r.Counts[checks.Fail],
		r.Counts[checks.NA], r.Counts[checks.Ignored], r.Counts[checks.Error])
}

func (r Report) markdown() string {
	var b strings.Builder
	cell := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ") }
	fmt.Fprintf(&b, "# Hardening report: %s\n\n", r.Server)
	fmt.Fprintf(&b, "- Date: %s\n- Score: **%.1f / 100** (grade **%s**)\n- Checks: %s\n- Scan: %s\n\n",
		r.StartedAt.Format("2006-01-02 15:04 MST"), r.Score, r.Grade, r.summary(), r.ScanID)
	b.WriteString("| Status | Severity | Check | CIS | Title | Evidence |\n|---|---|---|---|---|---|\n")
	for _, x := range r.Results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", x.Status, x.Severity, x.CheckID, cell(x.CIS),
			cell(x.Title), cell(x.Evidence))
	}
	if f := r.failed(); len(f) > 0 {
		b.WriteString("\n## Failed checks\n")
		for _, x := range f {
			fmt.Fprintf(&b, "\n### %s: %s\n\n- Severity: %s", x.CheckID, x.Title, x.Severity)
			if x.CIS != "" {
				fmt.Fprintf(&b, " (CIS %s)", x.CIS)
			}
			fmt.Fprintf(&b, "\n- Auto-fix: %s\n- Evidence: %s\n- Rationale: %s\n- Remediation: %s\n", x.AutoFix,
				x.Evidence, x.Rationale, x.Remediation)
		}
	}
	return b.String()
}

func (r Report) pdf() ([]byte, error) {
	p := fpdf.New("P", "mm", "A4", "")
	tr := p.UnicodeTranslatorFromDescriptor("")
	p.SetMargins(12, 12, 12)
	p.SetAutoPageBreak(true, 12)
	p.AddPage()
	p.SetFont("Helvetica", "B", 16)
	p.CellFormat(0, 9, tr("Hardening report: "+r.Server), "", 1, "", false, 0, "")
	p.SetFont("Helvetica", "", 10)
	p.CellFormat(0, 6, tr(fmt.Sprintf("Date %s   Score %.1f / 100   Grade %s", r.StartedAt.Format("2006-01-02 15:04 MST"),
		r.Score, r.Grade)), "", 1, "", false, 0, "")
	p.CellFormat(0, 6, tr(r.summary()), "", 1, "", false, 0, "")
	p.Ln(3)

	w := []float64{16, 18, 50, 18, 84}
	p.SetFont("Helvetica", "B", 9)
	p.SetFillColor(230, 230, 230)
	for i, h := range []string{"Status", "Severity", "Check", "CIS", "Title"} {
		p.CellFormat(w[i], 6, h, "1", 0, "", true, 0, "")
	}
	p.Ln(-1)
	p.SetFont("Helvetica", "", 8)
	for _, x := range r.Results {
		for i, v := range []string{x.Status, x.Severity, x.CheckID, x.CIS, x.Title} {
			p.CellFormat(w[i], 5, tr(clip(v, 60)), "1", 0, "", false, 0, "")
		}
		p.Ln(-1)
	}
	if f := r.failed(); len(f) > 0 {
		p.Ln(4)
		p.SetFont("Helvetica", "B", 12)
		p.CellFormat(0, 8, "Failed checks", "", 1, "", false, 0, "")
		for _, x := range f {
			p.SetFont("Helvetica", "B", 10)
			h := x.CheckID + ": " + x.Title + " (" + x.Severity
			if x.CIS != "" {
				h += ", CIS " + x.CIS
			}
			p.MultiCell(0, 5, tr(h+")"), "", "", false)
			p.SetFont("Helvetica", "", 9)
			for _, l := range []string{"Evidence: " + clip(x.Evidence, 600), "Rationale: " + x.Rationale,
				"Remediation: " + x.Remediation} {
				p.MultiCell(0, 4.5, tr(l), "", "", false)
			}
			p.Ln(2)
		}
	}
	var buf bytes.Buffer
	err := p.Output(&buf)
	return buf.Bytes(), err
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}
