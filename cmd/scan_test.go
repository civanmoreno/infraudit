package cmd

import (
	"fmt"
	"testing"

	"github.com/civanmoreno/infraudit/internal/remote"
	"github.com/civanmoreno/infraudit/internal/report"
)

func TestScanExitCode(t *testing.T) {
	tests := []struct {
		name    string
		results []remote.ScanResult
		want    int
	}{
		{
			name: "all pass",
			results: []remote.ScanResult{
				{Host: "h1", Report: &report.Report{Summary: report.Summary{Passed: 10}}},
			},
			want: 0,
		},
		{
			name: "warnings",
			results: []remote.ScanResult{
				{Host: "h1", Report: &report.Report{Summary: report.Summary{Passed: 8, Warnings: 2}}},
			},
			want: 1,
		},
		{
			name: "failures",
			results: []remote.ScanResult{
				{Host: "h1", Report: &report.Report{Summary: report.Summary{Passed: 5, Failures: 3}}},
			},
			want: 2,
		},
		{
			name: "operational error",
			results: []remote.ScanResult{
				{Host: "h1", Err: fmt.Errorf("connection refused")},
			},
			want: 3,
		},
		{
			name: "mixed: failure + error",
			results: []remote.ScanResult{
				{Host: "h1", Report: &report.Report{Summary: report.Summary{Failures: 1}}},
				{Host: "h2", Err: fmt.Errorf("timeout")},
			},
			want: 3,
		},
		{
			name: "worst wins across hosts",
			results: []remote.ScanResult{
				{Host: "h1", Report: &report.Report{Summary: report.Summary{Passed: 10}}},
				{Host: "h2", Report: &report.Report{Summary: report.Summary{Warnings: 2}}},
				{Host: "h3", Report: &report.Report{Summary: report.Summary{Failures: 1}}},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanExitCode(tt.results)
			if got != tt.want {
				t.Errorf("scanExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}
