package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteSARIF(t *testing.T) {
	r := &Report{
		Entries: []Entry{
			{ID: "AUTH-001", Name: "SSH root login disabled", Category: "auth", Severity: "CRITICAL", Status: "FAIL", Message: "Root login enabled", Remediation: "Set PermitRootLogin no"},
			{ID: "AUTH-003", Name: "Only root has UID 0", Category: "auth", Severity: "CRITICAL", Status: "PASS", Message: "Only root has UID 0"},
			{ID: "NET-001", Name: "Firewall active", Category: "network", Severity: "HIGH", Status: "WARN", Message: "No firewall detected"},
		},
		Summary: Summary{Total: 3, Passed: 1, Warnings: 1, Failures: 1, Score: 50, Grade: "F"},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	// Parse output
	var doc sarifDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify schema
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}

	run := doc.Runs[0]

	// Verify tool info
	if run.Tool.Driver.Name != "infraudit" {
		t.Errorf("tool name = %q, want infraudit", run.Tool.Driver.Name)
	}

	// Verify rules (all 3 entries should become rules)
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "AUTH-001" {
		t.Errorf("rule[0].id = %q, want AUTH-001", run.Tool.Driver.Rules[0].ID)
	}

	// Verify results (only non-PASS: AUTH-001 FAIL + NET-001 WARN)
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}

	// AUTH-001 should be "error" level
	if run.Results[0].RuleID != "AUTH-001" {
		t.Errorf("result[0].ruleId = %q, want AUTH-001", run.Results[0].RuleID)
	}
	if run.Results[0].Level != "error" {
		t.Errorf("result[0].level = %q, want error", run.Results[0].Level)
	}
	if len(run.Results[0].Fixes) != 1 {
		t.Fatalf("result[0].fixes = %d, want 1", len(run.Results[0].Fixes))
	}
	if run.Results[0].Fixes[0].Description.Text != "Set PermitRootLogin no" {
		t.Errorf("fix text = %q", run.Results[0].Fixes[0].Description.Text)
	}

	// NET-001 should be "warning" level
	if run.Results[1].Level != "warning" {
		t.Errorf("result[1].level = %q, want warning", run.Results[1].Level)
	}
}

func TestSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "9.5"},
		{"HIGH", "7.5"},
		{"MEDIUM", "5.0"},
		{"LOW", "2.5"},
		{"INFO", "0.0"},
	}
	for _, tt := range tests {
		got := severityToScore(tt.severity)
		if got != tt.want {
			t.Errorf("severityToScore(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestStatusToLevel(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"FAIL", "error"},
		{"WARN", "warning"},
		{"ERROR", "error"},
		{"PASS", "note"},
	}
	for _, tt := range tests {
		got := statusToLevel(tt.status)
		if got != tt.want {
			t.Errorf("statusToLevel(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestWriteSARIFNoFindings(t *testing.T) {
	r := &Report{
		Entries: []Entry{
			{ID: "AUTH-001", Name: "Test", Category: "auth", Severity: "HIGH", Status: "PASS", Message: "OK"},
		},
		Summary: Summary{Total: 1, Passed: 1, Score: 100, Grade: "A"},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var doc sarifDocument
	json.Unmarshal(buf.Bytes(), &doc)

	// Rules should still be present, but no results
	if len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(doc.Runs[0].Tool.Driver.Rules))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(doc.Runs[0].Results))
	}
}
