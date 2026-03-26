package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/report"
)

func writeTestReport(t *testing.T, dir, name string, r *report.Report) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

func TestLoadReport(t *testing.T) {
	dir := t.TempDir()

	r := &report.Report{
		Entries: []report.Entry{
			{ID: "AUTH-001", Name: "Test", Status: "PASS", Severity: "HIGH", Category: "auth"},
		},
		Summary: report.Summary{Total: 1, Passed: 1, Score: 100, Grade: "A"},
	}
	path := writeTestReport(t, dir, "report.json", r)

	loaded, err := loadReport(path)
	if err != nil {
		t.Fatalf("loadReport: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].ID != "AUTH-001" {
		t.Errorf("expected AUTH-001, got %s", loaded.Entries[0].ID)
	}
	if loaded.Summary.Score != 100 {
		t.Errorf("expected score 100, got %d", loaded.Summary.Score)
	}
}

func TestLoadReportFileNotFound(t *testing.T) {
	_, err := loadReport("/nonexistent/report.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadReportInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := loadReport(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestIndexEntries(t *testing.T) {
	entries := []report.Entry{
		{ID: "AUTH-001", Status: "PASS"},
		{ID: "NET-001", Status: "FAIL"},
		{ID: "FS-001", Status: "WARN"},
	}
	m := indexEntries(entries)
	if len(m) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(m))
	}
	if m["AUTH-001"].Status != "PASS" {
		t.Errorf("expected PASS for AUTH-001, got %s", m["AUTH-001"].Status)
	}
	if m["NET-001"].Status != "FAIL" {
		t.Errorf("expected FAIL for NET-001, got %s", m["NET-001"].Status)
	}
}

func TestStatusRank(t *testing.T) {
	tests := []struct {
		status string
		rank   int
	}{
		{"PASS", 0},
		{"WARN", 1},
		{"FAIL", 2},
		{"ERROR", 3},
		{"UNKNOWN", 4},
	}
	for _, tt := range tests {
		got := statusRank(tt.status)
		if got != tt.rank {
			t.Errorf("statusRank(%q) = %d, want %d", tt.status, got, tt.rank)
		}
	}
}

func TestChangeTypePriority(t *testing.T) {
	tests := []struct {
		changeType string
		priority   int
	}{
		{"regressed", 5},
		{"improved", 4},
		{"new", 3},
		{"removed", 2},
		{"unchanged", 1},
		{"other", 0},
	}
	for _, tt := range tests {
		got := changeTypePriority(tt.changeType)
		if got != tt.priority {
			t.Errorf("changeTypePriority(%q) = %d, want %d", tt.changeType, got, tt.priority)
		}
	}
}

func TestDiffDetectsImprovement(t *testing.T) {
	before := []report.Entry{
		{ID: "AUTH-001", Name: "SSH root login", Status: "FAIL", Severity: "CRITICAL", Category: "auth"},
	}
	after := []report.Entry{
		{ID: "AUTH-001", Name: "SSH root login", Status: "PASS", Severity: "CRITICAL", Category: "auth"},
	}

	beforeMap := indexEntries(before)
	afterMap := indexEntries(after)

	ae := afterMap["AUTH-001"]
	be := beforeMap["AUTH-001"]

	if statusRank(ae.Status) >= statusRank(be.Status) {
		t.Error("expected after to have better (lower) rank than before")
	}
}

func TestDiffDetectsRegression(t *testing.T) {
	before := []report.Entry{
		{ID: "NET-001", Name: "Firewall", Status: "PASS", Severity: "HIGH", Category: "network"},
	}
	after := []report.Entry{
		{ID: "NET-001", Name: "Firewall", Status: "FAIL", Severity: "HIGH", Category: "network"},
	}

	beforeMap := indexEntries(before)
	afterMap := indexEntries(after)

	ae := afterMap["NET-001"]
	be := beforeMap["NET-001"]

	if statusRank(ae.Status) <= statusRank(be.Status) {
		t.Error("expected after to have worse (higher) rank than before")
	}
}

func TestDiffDetectsNewCheck(t *testing.T) {
	before := []report.Entry{}
	after := []report.Entry{
		{ID: "LOG-001", Name: "Syslog", Status: "PASS", Severity: "MEDIUM", Category: "logging"},
	}

	beforeMap := indexEntries(before)
	afterMap := indexEntries(after)

	if _, exists := beforeMap["LOG-001"]; exists {
		t.Error("LOG-001 should not exist in before")
	}
	if _, exists := afterMap["LOG-001"]; !exists {
		t.Error("LOG-001 should exist in after")
	}
}

func TestDiffDetectsRemovedCheck(t *testing.T) {
	before := []report.Entry{
		{ID: "FS-001", Name: "SUID", Status: "WARN", Severity: "HIGH", Category: "filesystem"},
	}
	after := []report.Entry{}

	beforeMap := indexEntries(before)
	afterMap := indexEntries(after)

	if _, exists := beforeMap["FS-001"]; !exists {
		t.Error("FS-001 should exist in before")
	}
	if _, exists := afterMap["FS-001"]; exists {
		t.Error("FS-001 should not exist in after")
	}
}

func TestDiffDetectsUnchanged(t *testing.T) {
	before := []report.Entry{
		{ID: "AUTH-003", Name: "UID 0", Status: "PASS", Severity: "CRITICAL", Category: "auth"},
	}
	after := []report.Entry{
		{ID: "AUTH-003", Name: "UID 0", Status: "PASS", Severity: "CRITICAL", Category: "auth"},
	}

	beforeMap := indexEntries(before)
	afterMap := indexEntries(after)

	if beforeMap["AUTH-003"].Status != afterMap["AUTH-003"].Status {
		t.Error("expected same status for unchanged check")
	}
}
