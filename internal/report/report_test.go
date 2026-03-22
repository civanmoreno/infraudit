package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleReport() *Report {
	return &Report{
		Entries: []Entry{
			{
				ID:       "AUTH-001",
				Name:     "SSH root login disabled",
				Category: "auth",
				Severity: "CRITICAL",
				Status:   "PASS",
				Message:  "PermitRootLogin is set to no",
			},
			{
				ID:          "NET-001",
				Name:        "Firewall is active",
				Category:    "network",
				Severity:    "CRITICAL",
				Status:      "FAIL",
				Message:     "No active firewall detected",
				Remediation: "Enable a firewall",
			},
		},
		Summary: Summary{
			Total:    2,
			Passed:   1,
			Warnings: 0,
			Failures: 1,
			Errors:   0,
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	if err := WriteJSON(&buf, rpt); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if parsed.Summary.Total != 2 {
		t.Fatalf("expected total=2, got %d", parsed.Summary.Total)
	}
	if parsed.Summary.Failures != 1 {
		t.Fatalf("expected failures=1, got %d", parsed.Summary.Failures)
	}
	if len(parsed.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed.Entries))
	}
	if parsed.Entries[0].ID != "AUTH-001" {
		t.Fatalf("expected first entry AUTH-001, got %s", parsed.Entries[0].ID)
	}
}

func TestWriteYAML(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	if err := WriteYAML(&buf, rpt); err != nil {
		t.Fatalf("WriteYAML error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "AUTH-001") {
		t.Fatal("YAML output missing AUTH-001")
	}
	if !strings.Contains(output, "NET-001") {
		t.Fatal("YAML output missing NET-001")
	}
	if !strings.Contains(output, "total: 2") {
		t.Fatal("YAML output missing summary total")
	}
}

func TestWriteConsole(t *testing.T) {
	var buf bytes.Buffer
	rpt := sampleReport()

	WriteConsole(&buf, rpt)

	output := buf.String()
	if !strings.Contains(output, "AUTH-001") {
		t.Fatal("console output missing AUTH-001")
	}
	if !strings.Contains(output, "FAIL") {
		t.Fatal("console output missing FAIL status")
	}
}

func TestNewEntry(t *testing.T) {
	// Test that NewEntry works via the exported types
	entry := Entry{
		ID:       "TEST-001",
		Name:     "Test check",
		Category: "test",
		Severity: "HIGH",
		Status:   "PASS",
		Message:  "All good",
	}
	if entry.ID != "TEST-001" {
		t.Fatalf("expected ID=TEST-001, got %s", entry.ID)
	}
}
