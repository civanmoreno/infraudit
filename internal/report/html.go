package report

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/civanmoreno/infraudit/internal/version"
)

type htmlData struct {
	Version   string
	Hostname  string
	Timestamp string
	Summary   Summary
	Groups    []categoryGroup
	PassPct   int
	WarnPct   int
	FailPct   int
	ErrPct    int
	Score     int
	Grade     string
}

type categoryGroup struct {
	Name    string
	Label   string
	Prefix  string
	Entries []Entry
	Passed  int
	Warns   int
	Fails   int
	Errors  int
}

// WriteHTML writes a self-contained HTML report.
func WriteHTML(w io.Writer, r *Report) error {
	hostname, _ := os.Hostname()

	groups := groupByCategory(r.Entries)

	total := r.Summary.Total
	if total == 0 {
		total = 1
	}

	data := htmlData{
		Version:   version.Version,
		Hostname:  hostname,
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		Summary:   r.Summary,
		Groups:    groups,
		PassPct:   r.Summary.Passed * 100 / total,
		WarnPct:   r.Summary.Warnings * 100 / total,
		FailPct:   r.Summary.Failures * 100 / total,
		ErrPct:    r.Summary.Errors * 100 / total,
		Score:     r.Summary.Score,
		Grade:     r.Summary.Grade,
	}

	funcMap := template.FuncMap{
		"lower":    strings.ToLower,
		"gtZero":   func(f float64) bool { return f > 0 },
		"fmtFloat": func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"scoreClass": func(score int) string {
			switch {
			case score >= 90:
				return "score-a"
			case score >= 80:
				return "score-b"
			case score >= 70:
				return "score-c"
			case score >= 60:
				return "score-d"
			default:
				return "score-f"
			}
		},
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}
	return tmpl.Execute(w, data)
}

func groupByCategory(entries []Entry) []categoryGroup {
	grouped := make(map[string][]Entry)
	for _, e := range entries {
		grouped[e.Category] = append(grouped[e.Category], e)
	}

	var groups []categoryGroup
	// Ordered categories first
	for _, cat := range categoryOrder {
		if ents, ok := grouped[cat]; ok {
			g := buildGroup(cat, ents)
			groups = append(groups, g)
			delete(grouped, cat)
		}
	}
	// Any remaining
	for cat, ents := range grouped {
		groups = append(groups, buildGroup(cat, ents))
	}
	return groups
}

func buildGroup(cat string, entries []Entry) categoryGroup {
	sort.SliceStable(entries, func(i, j int) bool {
		return statusPriority(entries[i].Status) > statusPriority(entries[j].Status)
	})
	g := categoryGroup{
		Name:    cat,
		Label:   catLabel(cat),
		Prefix:  catPrefix(cat),
		Entries: entries,
	}
	for _, e := range entries {
		switch e.Status {
		case "PASS":
			g.Passed++
		case "WARN":
			g.Warns++
		case "FAIL":
			g.Fails++
		case "ERROR":
			g.Errors++
		}
	}
	return g
}

var htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>infraudit — Security Audit Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #111827; --bg2: #1f2937; --bg3: #374151;
  --text: #f3f4f6; --text2: #9ca3af; --text3: #6b7280;
  --green: #34d399; --yellow: #fbbf24; --red: #f87171; --purple: #a78bfa;
  --blue: #60a5fa; --cyan: #67e8f9;
  --green-bg: rgba(52,211,153,.1); --yellow-bg: rgba(251,191,36,.1);
  --red-bg: rgba(248,113,113,.1); --purple-bg: rgba(167,139,250,.1);
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Inter',sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }
code { font-family:'JetBrains Mono',monospace; font-size:.85em; }

.container { max-width:960px; margin:0 auto; padding:2rem 1.5rem; }

/* Header */
.header { text-align:center; padding:2.5rem 0 2rem; border-bottom:1px solid var(--bg3); margin-bottom:2rem; }
.header h1 { font-size:1.8rem; font-weight:700; color:var(--green); margin-bottom:.25rem; }
.header .meta { color:var(--text2); font-size:.9rem; }
.header .meta span { margin:0 .75rem; }

/* Summary cards */
.summary { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:1.5rem; }
.card { background:var(--bg2); border-radius:10px; padding:1.25rem; text-align:center; border-top:3px solid var(--bg3); }
.card.pass { border-top-color:var(--green); }
.card.warn { border-top-color:var(--yellow); }
.card.fail { border-top-color:var(--red); }
.card.err { border-top-color:var(--purple); }
.card .num { font-size:2.2rem; font-weight:700; line-height:1; }
.card.pass .num { color:var(--green); }
.card.warn .num { color:var(--yellow); }
.card.fail .num { color:var(--red); }
.card.err .num { color:var(--purple); }
.card .label { color:var(--text2); font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; margin-top:.25rem; }

/* Progress bar */
.progress-wrap { background:var(--bg2); border-radius:10px; padding:1rem 1.25rem; margin-bottom:2rem; }
.progress-label { font-size:.85rem; color:var(--text2); margin-bottom:.5rem; display:flex; justify-content:space-between; }
.progress-bar { height:12px; border-radius:6px; overflow:hidden; display:flex; background:var(--bg3); }
.progress-bar .seg-pass { background:var(--green); }
.progress-bar .seg-warn { background:var(--yellow); }
.progress-bar .seg-fail { background:var(--red); }
.progress-bar .seg-err  { background:var(--purple); }

/* Category sections */
.category { background:var(--bg2); border-radius:10px; margin-bottom:1.25rem; overflow:hidden; }
.cat-header { padding:1rem 1.25rem; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--bg3); }
.cat-header h2 { font-size:1rem; font-weight:600; }
.cat-header h2 .prefix { color:var(--cyan); margin-right:.5rem; }
.cat-stats { display:flex; gap:.75rem; font-size:.8rem; }
.cat-stats .st { padding:.15rem .5rem; border-radius:4px; }
.cat-stats .st-pass { color:var(--green); background:var(--green-bg); }
.cat-stats .st-warn { color:var(--yellow); background:var(--yellow-bg); }
.cat-stats .st-fail { color:var(--red); background:var(--red-bg); }
.cat-stats .st-err  { color:var(--purple); background:var(--purple-bg); }

/* Check rows */
.check { padding:.75rem 1.25rem; border-bottom:1px solid rgba(55,65,81,.5); display:grid; grid-template-columns:70px 90px 1fr; align-items:start; gap:.5rem; }
.check:last-child { border-bottom:none; }
.check:hover { background:rgba(255,255,255,.02); }

.badge { display:inline-block; padding:.15rem .5rem; border-radius:4px; font-size:.75rem; font-weight:600; text-transform:uppercase; }
.badge-pass { color:var(--green); background:var(--green-bg); }
.badge-warn { color:var(--yellow); background:var(--yellow-bg); }
.badge-fail { color:var(--red); background:var(--red-bg); }
.badge-error { color:var(--purple); background:var(--purple-bg); }

.sev { font-size:.7rem; font-weight:500; padding:.1rem .4rem; border-radius:3px; }
.sev-critical { color:var(--red); background:var(--red-bg); }
.sev-high { color:var(--yellow); background:var(--yellow-bg); }
.sev-medium { color:var(--cyan); background:rgba(103,232,249,.1); }
.sev-low { color:var(--blue); background:rgba(96,165,250,.1); }
.sev-info { color:var(--text3); background:rgba(107,114,128,.15); }

.check-id { color:var(--text3); font-family:'JetBrains Mono',monospace; font-size:.8rem; }
.check-msg { color:var(--text); font-size:.875rem; }
.check-fix { color:var(--text2); font-size:.8rem; margin-top:.25rem; padding:.4rem .6rem; background:var(--bg); border-radius:4px; border-left:2px solid var(--cyan); }
.check-fix::before { content:"↳ "; color:var(--cyan); }

/* Score card */
.score-wrap { background:var(--bg2); border-radius:10px; padding:1.5rem; margin-bottom:2rem; display:flex; align-items:center; gap:1.5rem; }
.score-circle { width:80px; height:80px; border-radius:50%; display:flex; flex-direction:column; align-items:center; justify-content:center; border:4px solid var(--bg3); }
.score-circle .score-num { font-size:1.6rem; font-weight:700; line-height:1; }
.score-circle .score-grade { font-size:.75rem; font-weight:600; opacity:.8; }
.score-info h3 { font-size:1rem; font-weight:600; margin-bottom:.25rem; }
.score-info p { font-size:.85rem; color:var(--text2); }
.score-a .score-circle { border-color:var(--green); }
.score-a .score-num, .score-a .score-grade { color:var(--green); }
.score-b .score-circle { border-color:var(--cyan); }
.score-b .score-num, .score-b .score-grade { color:var(--cyan); }
.score-c .score-circle { border-color:var(--yellow); }
.score-c .score-num, .score-c .score-grade { color:var(--yellow); }
.score-d .score-circle { border-color:var(--yellow); }
.score-d .score-num, .score-d .score-grade { color:var(--yellow); }
.score-f .score-circle { border-color:var(--red); }
.score-f .score-num, .score-f .score-grade { color:var(--red); }

/* Footer */
.footer { text-align:center; padding:2rem 0 1rem; color:var(--text3); font-size:.8rem; border-top:1px solid var(--bg3); margin-top:1rem; }

/* Responsive */
@media (max-width:640px) {
  .summary { grid-template-columns:repeat(2,1fr); }
  .check { grid-template-columns:60px 80px 1fr; }
  .cat-header { flex-direction:column; align-items:flex-start; gap:.5rem; }
}
@media print {
  body { background:#fff; color:#111; }
  .container { max-width:100%; }
  .card { border:1px solid #ddd; }
  .category { border:1px solid #ddd; }
  .check-fix { background:#f9f9f9; }
  .progress-bar { print-color-adjust:exact; -webkit-print-color-adjust:exact; }
}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>infraudit v{{.Version}} — Security Audit Report</h1>
    <div class="meta">
      <span>{{.Hostname}}</span>
      <span>{{.Timestamp}}</span>
      {{- if gtZero .Summary.Duration}}
      <span>{{fmtFloat .Summary.Duration}}s</span>
      {{- end}}
    </div>
  </div>

  <div class="summary">
    <div class="card pass"><div class="num">{{.Summary.Passed}}</div><div class="label">Passed</div></div>
    <div class="card warn"><div class="num">{{.Summary.Warnings}}</div><div class="label">Warnings</div></div>
    <div class="card fail"><div class="num">{{.Summary.Failures}}</div><div class="label">Failures</div></div>
    <div class="card err"><div class="num">{{.Summary.Errors}}</div><div class="label">Errors</div></div>
  </div>

  <div class="progress-wrap">
    <div class="progress-label">
      <span>{{.Summary.Passed}} / {{.Summary.Total}} checks passed</span>
      <span>{{.PassPct}}%</span>
    </div>
    <div class="progress-bar">
      <div class="seg-pass" style="width:{{.PassPct}}%"></div>
      <div class="seg-warn" style="width:{{.WarnPct}}%"></div>
      <div class="seg-fail" style="width:{{.FailPct}}%"></div>
      <div class="seg-err"  style="width:{{.ErrPct}}%"></div>
    </div>
  </div>

  <div class="score-wrap {{scoreClass .Score}}">
    <div class="score-circle">
      <div class="score-num">{{.Score}}</div>
      <div class="score-grade">{{.Grade}}</div>
    </div>
    <div class="score-info">
      <h3>Hardening Index</h3>
      <p>Score based on check results weighted by severity. CRITICAL checks have the highest impact on the score.</p>
    </div>
  </div>

  {{range .Groups}}
  <div class="category">
    <div class="cat-header">
      <h2><span class="prefix">{{.Prefix}}</span>{{.Label}}</h2>
      <div class="cat-stats">
        {{if gt .Passed 0}}<span class="st st-pass">{{.Passed}} passed</span>{{end}}
        {{if gt .Warns 0}}<span class="st st-warn">{{.Warns}} warn</span>{{end}}
        {{if gt .Fails 0}}<span class="st st-fail">{{.Fails}} fail</span>{{end}}
        {{if gt .Errors 0}}<span class="st st-err">{{.Errors}} err</span>{{end}}
      </div>
    </div>
    {{range .Entries}}
    <div class="check">
      <div>
        <span class="badge badge-{{lower .Status}}">{{.Status}}</span>
      </div>
      <div>
        <span class="check-id">{{.ID}}</span><br>
        <span class="sev sev-{{lower .Severity}}">{{.Severity}}</span>
      </div>
      <div>
        <div class="check-msg">{{.Message}}</div>
        {{if .Remediation}}
        <div class="check-fix">{{.Remediation}}</div>
        {{end}}
      </div>
    </div>
    {{end}}
  </div>
  {{end}}

  <div class="footer">
    Generated by infraudit v{{.Version}}
  </div>

</div>
</body>
</html>
`
