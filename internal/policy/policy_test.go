package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/report"
)

func makeReport(entries []report.Entry, score int) *report.Report {
	return &report.Report{
		Entries:    entries,
		AllEntries: entries,
		Summary:    report.Summary{Score: score, Grade: "C"},
	}
}

func TestEnforceMinScore(t *testing.T) {
	p := &Policy{MinScore: 80, MaxCritical: -1, MaxHigh: -1}
	r := makeReport(nil, 72)

	result := Enforce(p, r)
	if result.Passed {
		t.Error("expected policy to fail on low score")
	}
	if len(result.Violations) != 1 || result.Violations[0].Rule != "min_score" {
		t.Errorf("violations = %+v", result.Violations)
	}
}

func TestEnforceMinScorePass(t *testing.T) {
	p := &Policy{MinScore: 80, MaxCritical: -1, MaxHigh: -1}
	r := makeReport(nil, 85)

	result := Enforce(p, r)
	if !result.Passed {
		t.Error("expected policy to pass")
	}
}

func TestEnforceMaxCritical(t *testing.T) {
	p := &Policy{MaxCritical: 0, MaxHigh: -1}
	entries := []report.Entry{
		{ID: "AUTH-001", Severity: "CRITICAL", Status: "FAIL"},
		{ID: "AUTH-003", Severity: "CRITICAL", Status: "PASS"},
	}
	r := makeReport(entries, 50)

	result := Enforce(p, r)
	if result.Passed {
		t.Error("expected policy to fail on critical findings")
	}
}

func TestEnforceMaxHigh(t *testing.T) {
	p := &Policy{MaxCritical: -1, MaxHigh: 1}
	entries := []report.Entry{
		{ID: "AUTH-002", Severity: "HIGH", Status: "FAIL"},
		{ID: "NET-001", Severity: "HIGH", Status: "FAIL"},
		{ID: "FS-001", Severity: "HIGH", Status: "PASS"},
	}
	r := makeReport(entries, 50)

	result := Enforce(p, r)
	if result.Passed {
		t.Error("expected policy to fail (2 high > max 1)")
	}
}

func TestEnforceRequiredPass(t *testing.T) {
	p := &Policy{MaxCritical: -1, MaxHigh: -1, RequiredPass: []string{"AUTH-001", "NET-001"}}
	entries := []report.Entry{
		{ID: "AUTH-001", Severity: "CRITICAL", Status: "PASS"},
		{ID: "NET-001", Severity: "CRITICAL", Status: "FAIL"},
	}
	r := makeReport(entries, 50)

	result := Enforce(p, r)
	if result.Passed {
		t.Error("expected policy to fail (NET-001 not PASS)")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
}

func TestEnforceRequiredPassMissing(t *testing.T) {
	p := &Policy{MaxCritical: -1, MaxHigh: -1, RequiredPass: []string{"FAKE-001"}}
	r := makeReport(nil, 100)

	result := Enforce(p, r)
	if result.Passed {
		t.Error("expected policy to fail (check not found)")
	}
}

func TestEnforceIgnore(t *testing.T) {
	p := &Policy{MaxCritical: 0, MaxHigh: -1, Ignore: []string{"AUTH-001"}}
	entries := []report.Entry{
		{ID: "AUTH-001", Severity: "CRITICAL", Status: "FAIL"},
	}
	r := makeReport(entries, 50)

	result := Enforce(p, r)
	if !result.Passed {
		t.Error("expected policy to pass (AUTH-001 is ignored)")
	}
}

func TestEnforceAllPass(t *testing.T) {
	p := &Policy{MinScore: 70, MaxCritical: 0, MaxHigh: 2, RequiredPass: []string{"AUTH-001"}}
	entries := []report.Entry{
		{ID: "AUTH-001", Severity: "CRITICAL", Status: "PASS"},
		{ID: "NET-002", Severity: "HIGH", Status: "WARN"},
	}
	r := makeReport(entries, 85)

	result := Enforce(p, r)
	if !result.Passed {
		t.Errorf("expected policy to pass, violations: %+v", result.Violations)
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	p := Policy{MinScore: 80, MaxCritical: 0, MaxHigh: 3, RequiredPass: []string{"AUTH-001"}, Ignore: []string{"HARD-009"}}
	data, _ := json.Marshal(p)
	os.WriteFile(path, data, 0600)

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.MinScore != 80 {
		t.Errorf("MinScore = %d, want 80", loaded.MinScore)
	}
	if len(loaded.RequiredPass) != 1 || loaded.RequiredPass[0] != "AUTH-001" {
		t.Errorf("RequiredPass = %v", loaded.RequiredPass)
	}
	if len(loaded.Ignore) != 1 || loaded.Ignore[0] != "HARD-009" {
		t.Errorf("Ignore = %v", loaded.Ignore)
	}
}

func TestLoadPolicyNotFound(t *testing.T) {
	_, err := Load("/nonexistent/policy.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadPolicyInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFormatViolations(t *testing.T) {
	result := Result{
		Passed: false,
		Violations: []Violation{
			{Rule: "min_score", Details: "Score 60 is below minimum 80"},
		},
	}
	out := FormatViolations(result)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatViolationsEmpty(t *testing.T) {
	result := Result{Passed: true}
	out := FormatViolations(result)
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}
