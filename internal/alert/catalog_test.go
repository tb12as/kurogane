package alert

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// every metric the collectors emit and every metric the contracts table lists must be in the catalog
func TestCatalogCoversCollectorsAndContracts(t *testing.T) {
	names := map[string]string{}
	src, _ := filepath.Glob("../collector/*.go")
	emit := regexp.MustCompile(`(?:add|addL)\(out, "([a-z0-9_.]+)"|Metric: "([a-z0-9_.]+)"`)
	for _, f := range src {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range emit.FindAllStringSubmatch(string(b), -1) {
			names[m[1]+m[2]] = f
		}
	}
	// redis metrics are emitted through a local add() helper: take them from the contracts table too
	b, err := os.ReadFile("../../docs/CONTRACTS.md")
	if err != nil {
		t.Fatal(err)
	}
	table := string(b)[strings.Index(string(b), "## Metric catalog"):]
	table = table[:strings.Index(table, "\n## ")]
	name := regexp.MustCompile("`([a-z0-9_]+\\.[a-z0-9_.]+)(?:\\{[^`]*\\})?`")
	for _, line := range strings.Split(table, "\n") {
		cols := strings.Split(line, "|")
		if len(cols) < 4 {
			continue
		}
		for _, m := range name.FindAllStringSubmatch(cols[2], -1) { // the metrics column only
			names[m[1]] = "CONTRACTS.md"
		}
	}
	if len(names) < 90 {
		t.Fatalf("only %d metric names found: the extraction is broken", len(names))
	}
	for n, where := range names {
		if _, ok := LookupMetric(n); !ok {
			t.Errorf("metric %s (from %s) is not in the catalog", n, where)
		}
	}
}

func TestCatalogEntries(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Catalog() {
		if seen[d.Name] {
			t.Errorf("duplicate %s", d.Name)
		}
		seen[d.Name] = true
		if d.Group == "" || d.Title == "" || len(d.Description) < 20 || d.Unit == "" || len(d.Presets) == 0 ||
			(d.DefaultOp != ">" && d.DefaultOp != "<" && d.DefaultOp != "==") {
			t.Errorf("incomplete entry %+v", d)
		}
		if d.Unit == "bool" && (d.States["0"] == "" || d.States["1"] == "") {
			t.Errorf("%s: bool without state words", d.Name)
		}
		if strings.Contains(d.Description, "ServerKeeper") {
			t.Errorf("%s: old product name", d.Name)
		}
	}
}

func TestBuiltinRulesFitTheBuilder(t *testing.T) {
	for _, r := range builtins {
		if r.tmpl == "" {
			continue
		}
		expr := r.rule(nil).Expr
		c, err := FlatConditions(expr)
		if err != nil || c == nil || len(c.Items) == 0 {
			t.Errorf("%s: %q gives %+v %v", r.id, expr, c, err)
		}
		if err := CheckMetrics(expr); err != nil {
			t.Errorf("%s: %v", r.id, err)
		}
		if s := Summary(expr); s == expr || strings.Contains(s, "_") && !strings.Contains(s, "(") {
			t.Errorf("%s: summary %q", r.id, s)
		}
	}
}

func TestFlatConditionsAndSummary(t *testing.T) {
	c, err := FlatConditions(`disk.used_pct{mount="/"} > 85 and (cpu.total_pct >= 50 and load.1 > 4)`)
	if err != nil || c.Join != "and" || len(c.Items) != 3 || c.Items[0].Labels["mount"] != "/" || c.Items[1].Op != ">=" {
		t.Fatalf("flat = %+v %v", c, err)
	}
	if c, err := FlatConditions(`cpu.total_pct > 90 or (mem.used_pct > 80 and swap.used_pct > 10)`); err != nil || c != nil {
		t.Fatalf("mixed = %+v %v", c, err)
	}
	if _, err := FlatConditions(`cpu >`); err == nil {
		t.Fatal("bad expression parsed")
	}
	for expr, want := range map[string]string{
		`cpu.total_pct > 90`:                               "CPU usage, all cores above 90 %",
		`disk.used_pct{mount="/data"} >= 85`:               "Disk space used (mount /data) at or above 85 %",
		`mem.available_pct < 10 or swap.used_pct > 50`:     "Memory available below 10 % or Swap used above 50 %",
		`service.active < 1`:                               "Service is not running",
		`redis.up == 1`:                                    "Redis is up",
		`cert.days_left < 14`:                              "Days until certificate expiry below 14 days",
		`net.rx_bps_total > 10485760`:                      "Inbound traffic, all interfaces above 10.0 MB/s",
		`custom.metric > 3`:                                "custom.metric above 3",
		`cpu.total_pct > 1 or (load.1 > 2 and load.5 > 3)`: `cpu.total_pct > 1 or (load.1 > 2 and load.5 > 3)`,
	} {
		if got := Summary(expr); got != want {
			t.Errorf("Summary(%s) = %q, want %q", expr, got, want)
		}
	}
}

func TestCheckMetrics(t *testing.T) {
	if err := CheckMetrics(`cpu.total > 9`); err == nil || !strings.Contains(err.Error(), "did you mean cpu.total_pct?") {
		t.Fatalf("typo: %v", err)
	}
	if err := CheckMetrics(`disk.used_pct{device="sda"} > 9`); err == nil || !strings.Contains(err.Error(), "use mount") {
		t.Fatalf("label: %v", err)
	}
	if err := CheckMetrics(`cpu.total_pct{x="1"} > 9`); err == nil || !strings.Contains(err.Error(), "it has no labels") {
		t.Fatalf("no labels: %v", err)
	}
	if err := CheckMetrics(`zzzzzzzzzzzz > 1`); err == nil || strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("far: %v", err)
	}
	if err := CheckMetrics(`disk.used_pct{mount="/"} > 85 and redis.up{instance="cache"} < 1`); err != nil {
		t.Fatal(err)
	}
	if err := CheckMetrics(`cpu >`); err == nil {
		t.Fatal("syntax")
	}
	if FormatValue(MetricDef{Unit: "days"}, 1) != "1 day" || FormatValue(MetricDef{Unit: "ratio"}, 3) != "3×" {
		t.Fatal("format")
	}
}
