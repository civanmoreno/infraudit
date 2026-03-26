package remote

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/civanmoreno/infraudit/internal/report"
)

// ANSI escape codes.
const (
	rst     = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
)

// MultiHostReport holds results from scanning multiple hosts.
type MultiHostReport struct {
	Hosts   []HostReport `json:"hosts"`
	Summary FleetSummary `json:"summary"`
}

// HostReport holds the result for a single host.
type HostReport struct {
	Host   string         `json:"host"`
	Error  string         `json:"error,omitempty"`
	Report *report.Report `json:"report,omitempty"`
}

// FleetSummary holds aggregate stats across all hosts.
type FleetSummary struct {
	TotalHosts   int `json:"total_hosts"`
	SuccessHosts int `json:"success_hosts"`
	FailedHosts  int `json:"failed_hosts"`
}

// BuildMultiHostReport creates a MultiHostReport from scan results.
func BuildMultiHostReport(results []ScanResult) *MultiHostReport {
	mhr := &MultiHostReport{
		Hosts: make([]HostReport, len(results)),
	}
	mhr.Summary.TotalHosts = len(results)

	for i, r := range results {
		hr := HostReport{Host: r.Host}
		if r.Err != nil {
			hr.Error = r.Err.Error()
			mhr.Summary.FailedHosts++
		} else {
			hr.Report = r.Report
			mhr.Summary.SuccessHosts++
		}
		mhr.Hosts[i] = hr
	}
	return mhr
}

// WriteConsole writes a multi-host report to the console.
func WriteConsole(w io.Writer, results []ScanResult) {
	for _, r := range results {
		fmt.Fprintf(w, "\n  %s%s%s\n", dim, strings.Repeat("═", 60), rst)
		if r.Err != nil {
			fmt.Fprintf(w, "  %s%s%s — %s%sERROR%s: %s\n",
				bold, r.Host, rst, red, bold, rst, r.Err)
			fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("═", 60), rst)
			continue
		}
		fmt.Fprintf(w, "  %s%s%s — Score: %s%d/100 (%s)%s\n",
			bold, r.Host, rst,
			scoreColor(r.Report.Summary.Score),
			r.Report.Summary.Score, r.Report.Summary.Grade, rst)
		fmt.Fprintf(w, "  %s%s%s\n\n", dim, strings.Repeat("═", 60), rst)
		report.WriteConsole(w, r.Report)
	}

	// Fleet summary table
	writeFleetSummary(w, results)
}

// WriteJSON writes a multi-host report as JSON.
func WriteJSON(w io.Writer, results []ScanResult) error {
	mhr := BuildMultiHostReport(results)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(mhr)
}

// WriteSingleConsole writes a single-host result using the standard console report.
func WriteSingleConsole(w io.Writer, result ScanResult) {
	if result.Err != nil {
		fmt.Fprintf(w, "\n  %s%sERROR%s scanning %s: %s\n\n", red, bold, rst, result.Host, result.Err)
		return
	}
	fmt.Fprintf(w, "\n  %sRemote audit: %s%s%s\n", dim, bold, result.Host, rst)
	report.WriteConsole(w, result.Report)
}

func writeFleetSummary(w io.Writer, results []ScanResult) {
	fmt.Fprintf(w, "\n  %s%s%s\n", dim, strings.Repeat("═", 60), rst)
	fmt.Fprintf(w, "  %sFLEET SUMMARY%s\n", bold, rst)
	fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("─", 60), rst)
	fmt.Fprintf(w, "  %-30s %6s %6s %9s %9s\n",
		bold+"Host"+rst, "Score", "Grade", "Failures", "Warnings")
	fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("─", 60), rst)

	for _, r := range results {
		host := r.Host
		if len(host) > 30 {
			host = host[:27] + "..."
		}
		if r.Err != nil {
			fmt.Fprintf(w, "  %-30s %s%6s %6s%s %9s\n",
				host, red+bold, "ERR", "-", rst, truncate(r.Err.Error(), 20))
			continue
		}
		s := r.Report.Summary
		fmt.Fprintf(w, "  %-30s %s%6d %6s%s %9d %9d\n",
			host,
			scoreColor(s.Score), s.Score, s.Grade, rst,
			s.Failures, s.Warnings)
	}
	fmt.Fprintf(w, "  %s%s%s\n\n", dim, strings.Repeat("═", 60), rst)
}

func scoreColor(score int) string {
	switch {
	case score >= 90:
		return green + bold
	case score >= 80:
		return cyan + bold
	case score >= 70:
		return yellow + bold
	case score >= 60:
		return yellow
	default:
		return red + bold
	}
}
