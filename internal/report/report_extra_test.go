package report

import (
	"bytes"
	"strings"
	"testing"
)

// --- WriteMarkdown ---

func TestWriteMarkdown_BasicOutput(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "AUTH-001", Name: "SSH root login disabled", Category: "auth", Severity: "CRITICAL", Status: "PASS", Message: "PermitRootLogin is set to no"},
			{ID: "NET-001", Name: "Firewall active", Category: "network", Severity: "HIGH", Status: "FAIL", Message: "No firewall detected", Remediation: "Enable firewall"},
			{ID: "HARD-003", Name: "ASLR enabled", Category: "hardening", Severity: "HIGH", Status: "PASS", Message: "ASLR is fully enabled"},
		},
		Summary: Summary{
			Total: 3, Passed: 2, Warnings: 0, Failures: 1,
			Score: 66, Grade: "D",
		},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rpt); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}

	out := buf.String()

	// Verify header
	if !strings.Contains(out, "# infraudit") {
		t.Error("missing markdown header")
	}

	// Verify table header is present
	if !strings.Contains(out, "| Status | ID | Severity | Finding |") {
		t.Error("missing markdown table header")
	}

	// Verify entries appear
	if !strings.Contains(out, "`AUTH-001`") {
		t.Error("missing AUTH-001 in markdown")
	}
	if !strings.Contains(out, "`NET-001`") {
		t.Error("missing NET-001 in markdown")
	}
	if !strings.Contains(out, "`HARD-003`") {
		t.Error("missing HARD-003 in markdown")
	}

	// Verify remediation appears inline
	if !strings.Contains(out, "Enable firewall") {
		t.Error("missing remediation text in markdown")
	}

	// Verify hardening index
	if !strings.Contains(out, "66/100") {
		t.Error("missing hardening index in markdown")
	}

	// Verify category sections
	if !strings.Contains(out, "AUTH") {
		t.Error("missing AUTH category section")
	}
	if !strings.Contains(out, "NET") {
		t.Error("missing NET category section")
	}
}

func TestWriteMarkdown_SkippedStatus(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "SVC-001", Name: "Test", Category: "services", Severity: "LOW", Status: "SKIPPED", Message: "Not applicable"},
			{ID: "SVC-002", Name: "Test2", Category: "services", Severity: "MEDIUM", Status: "PASS", Message: "OK"},
		},
		Summary: Summary{
			Total: 2, Passed: 1, Skipped: 1,
			Score: 100, Grade: "A",
		},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rpt); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SKIPPED") {
		t.Error("markdown output should contain SKIPPED status")
	}
	if !strings.Contains(out, "1** skipped") {
		t.Error("markdown summary should mention skipped count")
	}
}

func TestWriteMarkdown_PipeEscaping(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "TEST-001", Name: "Pipe test", Category: "auth", Severity: "LOW", Status: "WARN", Message: "value|other"},
		},
		Summary: Summary{Total: 1, Warnings: 1, Score: 50, Grade: "F"},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rpt); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "value|other") {
		t.Error("pipe character should be escaped in markdown table")
	}
	if !strings.Contains(out, `value\|other`) {
		t.Error("pipe should be escaped as \\|")
	}
}

// --- WriteConsole ---

func TestWriteConsole_NoPanic(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "AUTH-001", Name: "Test", Category: "auth", Severity: "CRITICAL", Status: "PASS", Message: "OK"},
			{ID: "NET-001", Name: "Test", Category: "network", Severity: "HIGH", Status: "FAIL", Message: "Bad", Remediation: "Fix it"},
			{ID: "LOG-001", Name: "Test", Category: "logging", Severity: "MEDIUM", Status: "WARN", Message: "Meh"},
			{ID: "SVC-001", Name: "Test", Category: "services", Severity: "LOW", Status: "ERROR", Message: "Err"},
			{ID: "HARD-001", Name: "Test", Category: "hardening", Severity: "LOW", Status: "SKIPPED", Message: "Skipped"},
		},
		AllEntries: []Entry{
			{Severity: "CRITICAL", Status: "PASS"},
			{Severity: "HIGH", Status: "FAIL"},
			{Severity: "MEDIUM", Status: "WARN"},
			{Severity: "LOW", Status: "ERROR"},
			{Severity: "LOW", Status: "SKIPPED"},
		},
		Summary: Summary{
			Total: 5, Passed: 1, Warnings: 1, Failures: 1, Errors: 1, Skipped: 1,
			Score: 50, Grade: "F",
		},
	}

	var buf bytes.Buffer
	// Should not panic even with all status types
	WriteConsole(&buf, rpt)

	out := buf.String()
	if out == "" {
		t.Fatal("console output is empty")
	}
	if !strings.Contains(out, "AUTH-001") {
		t.Error("console output missing AUTH-001")
	}
	if !strings.Contains(out, "1 skip") {
		t.Error("console output should show skipped count")
	}
}

func TestWriteConsole_LongMessage(t *testing.T) {
	long := strings.Repeat("x", 100)
	rpt := &Report{
		Entries: []Entry{
			{ID: "T-001", Name: "Long", Category: "auth", Severity: "LOW", Status: "PASS", Message: long},
		},
		Summary: Summary{Total: 1, Passed: 1, Score: 100, Grade: "A"},
	}

	var buf bytes.Buffer
	WriteConsole(&buf, rpt)

	out := buf.String()
	// The message should be truncated with "..."
	if !strings.Contains(out, "...") {
		t.Error("long message should be truncated with ellipsis")
	}
}

func TestWriteConsole_EmptyReport(t *testing.T) {
	rpt := &Report{
		Summary: Summary{Total: 0},
	}

	var buf bytes.Buffer
	// Should not panic on empty report
	WriteConsole(&buf, rpt)
}

func TestWriteConsole_OSInfo(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "T-001", Name: "Test", Category: "auth", Severity: "LOW", Status: "PASS", Message: "OK"},
		},
		Summary: Summary{
			Total: 1, Passed: 1, Score: 100, Grade: "A",
			OSInfo: &OSInfo{
				ID: "ubuntu", Name: "Ubuntu", Version: "22.04",
				Family: "debian", PkgManager: "apt", InitSystem: "systemd", Arch: "amd64",
			},
		},
	}

	var buf bytes.Buffer
	WriteConsole(&buf, rpt)

	out := buf.String()
	if !strings.Contains(out, "Ubuntu") {
		t.Error("console output should show OS name")
	}
	if !strings.Contains(out, "22.04") {
		t.Error("console output should show OS version")
	}
}

// --- severityBreakdown ---

func TestSeverityBreakdown_AllStatuses(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "FAIL"},
		{Severity: "CRITICAL", Status: "WARN"},
		{Severity: "HIGH", Status: "FAIL"},
		{Severity: "MEDIUM", Status: "WARN"},
		{Severity: "LOW", Status: "FAIL"},
		{Severity: "CRITICAL", Status: "PASS"}, // should be excluded
		{Severity: "HIGH", Status: "PASS"},     // should be excluded
	}

	c := severityBreakdown(entries)

	if c.critical != 2 {
		t.Errorf("expected 2 critical, got %d", c.critical)
	}
	if c.high != 1 {
		t.Errorf("expected 1 high, got %d", c.high)
	}
	if c.medium != 1 {
		t.Errorf("expected 1 medium, got %d", c.medium)
	}
	if c.low != 1 {
		t.Errorf("expected 1 low, got %d", c.low)
	}
}

func TestSeverityBreakdown_AllPass(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "PASS"},
		{Severity: "HIGH", Status: "PASS"},
	}

	c := severityBreakdown(entries)

	if c.critical+c.high+c.medium+c.low != 0 {
		t.Error("all-pass should have zero findings")
	}
}

func TestSeverityBreakdown_Empty(t *testing.T) {
	c := severityBreakdown(nil)
	if c.critical+c.high+c.medium+c.low != 0 {
		t.Error("empty entries should have zero findings")
	}
}

func TestSeverityBreakdown_SkippedAndError(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "SKIPPED"},
		{Severity: "HIGH", Status: "ERROR"},
	}

	c := severityBreakdown(entries)

	// SKIPPED and ERROR are not PASS, so they count as findings
	if c.critical != 1 {
		t.Errorf("expected 1 critical (SKIPPED counts as non-pass), got %d", c.critical)
	}
	if c.high != 1 {
		t.Errorf("expected 1 high (ERROR counts as non-pass), got %d", c.high)
	}
}

// --- statusPriority ---

func TestStatusPriority_Ordering(t *testing.T) {
	statuses := []string{"FAIL", "ERROR", "WARN", "PASS", "SKIPPED"}
	expected := []int{5, 4, 3, 2, 1}

	for i, s := range statuses {
		got := statusPriority(s)
		if got != expected[i] {
			t.Errorf("statusPriority(%q) = %d, want %d", s, got, expected[i])
		}
	}
}

func TestStatusPriority_Unknown(t *testing.T) {
	if got := statusPriority("UNKNOWN"); got != 0 {
		t.Errorf("statusPriority(UNKNOWN) = %d, want 0", got)
	}
	if got := statusPriority(""); got != 0 {
		t.Errorf("statusPriority(\"\") = %d, want 0", got)
	}
}

func TestStatusPriority_FailHigherThanWarn(t *testing.T) {
	if statusPriority("FAIL") <= statusPriority("WARN") {
		t.Error("FAIL should have higher priority than WARN")
	}
	if statusPriority("WARN") <= statusPriority("PASS") {
		t.Error("WARN should have higher priority than PASS")
	}
	if statusPriority("PASS") <= statusPriority("SKIPPED") {
		t.Error("PASS should have higher priority than SKIPPED")
	}
}

// --- visibleLen ---

func TestVisibleLen_Plain(t *testing.T) {
	if got := visibleLen("hello"); got != 5 {
		t.Errorf("visibleLen(\"hello\") = %d, want 5", got)
	}
}

func TestVisibleLen_Empty(t *testing.T) {
	if got := visibleLen(""); got != 0 {
		t.Errorf("visibleLen(\"\") = %d, want 0", got)
	}
}

func TestVisibleLen_ANSIColor(t *testing.T) {
	colored := "\033[31mRED\033[0m"
	if got := visibleLen(colored); got != 3 {
		t.Errorf("visibleLen with ANSI red = %d, want 3", got)
	}
}

func TestVisibleLen_MultipleCodes(t *testing.T) {
	// bold + color + text + reset
	s := "\033[1m\033[32mOK\033[0m"
	if got := visibleLen(s); got != 2 {
		t.Errorf("visibleLen with bold+green = %d, want 2", got)
	}
}

func TestVisibleLen_NoEscapes(t *testing.T) {
	if got := visibleLen("PASS"); got != 4 {
		t.Errorf("visibleLen(\"PASS\") = %d, want 4", got)
	}
}

func TestVisibleLen_OnlyEscapes(t *testing.T) {
	s := "\033[31m\033[0m"
	if got := visibleLen(s); got != 0 {
		t.Errorf("visibleLen(only escapes) = %d, want 0", got)
	}
}

// --- ComputeScore with SKIPPED ---

func TestComputeScore_SkippedExcluded(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "PASS"},  // 10/10
		{Severity: "HIGH", Status: "SKIPPED"},   // excluded
		{Severity: "MEDIUM", Status: "SKIPPED"}, // excluded
	}
	score := ComputeScore(entries)
	// Only CRITICAL counts: 10/10 = 100
	if score != 100 {
		t.Fatalf("expected 100 with SKIPPED excluded, got %d", score)
	}
}

func TestComputeScore_AllSkipped(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "SKIPPED"},
		{Severity: "HIGH", Status: "SKIPPED"},
	}
	score := ComputeScore(entries)
	// No scorable checks -> 100
	if score != 100 {
		t.Fatalf("expected 100 with all SKIPPED, got %d", score)
	}
}

func TestComputeScore_MixedWithSkipped(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "PASS"},  // 10/10
		{Severity: "HIGH", Status: "FAIL"},      // 0/5
		{Severity: "MEDIUM", Status: "SKIPPED"}, // excluded
		{Severity: "LOW", Status: "WARN"},       // 0/1
	}
	// earned=10, possible=16 -> 62
	score := ComputeScore(entries)
	if score != 62 {
		t.Fatalf("expected 62, got %d", score)
	}
}

// --- YAML OSInfo rendering ---

func TestWriteYAML_WithOSInfo(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "T-001", Name: "Test", Category: "auth", Severity: "LOW", Status: "PASS", Message: "OK"},
		},
		Summary: Summary{
			Total: 1, Passed: 1, Score: 100, Grade: "A",
			OSInfo: &OSInfo{
				ID: "ubuntu", Name: "Ubuntu", Version: "22.04",
				Family: "debian", PkgManager: "apt", InitSystem: "systemd", Arch: "amd64",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteYAML(&buf, rpt); err != nil {
		t.Fatalf("WriteYAML error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "os:") {
		t.Error("YAML missing os section")
	}
	if !strings.Contains(out, "id: ubuntu") {
		t.Error("YAML missing os id")
	}
	if !strings.Contains(out, "family: debian") {
		t.Error("YAML missing os family")
	}
	if !strings.Contains(out, "pkg_manager: apt") {
		t.Error("YAML missing os pkg_manager")
	}
	if !strings.Contains(out, "init_system: systemd") {
		t.Error("YAML missing os init_system")
	}
	if !strings.Contains(out, "arch: amd64") {
		t.Error("YAML missing os arch")
	}
}

func TestWriteYAML_WithoutOSInfo(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "T-001", Name: "Test", Category: "auth", Severity: "LOW", Status: "PASS", Message: "OK"},
		},
		Summary: Summary{
			Total: 1, Passed: 1, Score: 100, Grade: "A",
		},
	}

	var buf bytes.Buffer
	if err := WriteYAML(&buf, rpt); err != nil {
		t.Fatalf("WriteYAML error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "  os:") {
		t.Error("YAML should not contain os section when OSInfo is nil")
	}
}

func TestWriteYAML_WithSkipped(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "T-001", Name: "Test", Category: "auth", Severity: "LOW", Status: "SKIPPED", Message: "Not applicable"},
		},
		Summary: Summary{
			Total: 1, Skipped: 1, Score: 100, Grade: "A",
		},
	}

	var buf bytes.Buffer
	if err := WriteYAML(&buf, rpt); err != nil {
		t.Fatalf("WriteYAML error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "status: SKIPPED") {
		t.Error("YAML should contain SKIPPED status")
	}
	if !strings.Contains(out, "skipped: 1") {
		t.Error("YAML summary should show skipped count")
	}
}

func TestWriteYAML_Duration(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{},
		Summary: Summary{
			Total: 0, Score: 100, Grade: "A", Duration: 3.5,
		},
	}

	var buf bytes.Buffer
	if err := WriteYAML(&buf, rpt); err != nil {
		t.Fatalf("WriteYAML error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "duration_seconds: 3.5") {
		t.Error("YAML should contain duration_seconds")
	}
}

func TestWriteYAML_Remediation(t *testing.T) {
	rpt := &Report{
		Entries: []Entry{
			{ID: "T-001", Name: "Test", Category: "auth", Severity: "HIGH", Status: "FAIL",
				Message: "Bad", Remediation: "Fix: run 'cmd'"},
		},
		Summary: Summary{Total: 1, Failures: 1, Score: 0, Grade: "F"},
	}

	var buf bytes.Buffer
	if err := WriteYAML(&buf, rpt); err != nil {
		t.Fatalf("WriteYAML error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "remediation:") {
		t.Error("YAML should contain remediation field")
	}
}

// --- padRight ---

func TestPadRight_Plain(t *testing.T) {
	got := padRight("hi", 5)
	if got != "hi   " {
		t.Errorf("padRight(\"hi\", 5) = %q, want \"hi   \"", got)
	}
}

func TestPadRight_ExactWidth(t *testing.T) {
	got := padRight("hello", 5)
	if got != "hello" {
		t.Errorf("padRight(\"hello\", 5) = %q, want \"hello\"", got)
	}
}

func TestPadRight_OverWidth(t *testing.T) {
	got := padRight("toolong", 3)
	if got != "toolong" {
		t.Errorf("padRight should not truncate, got %q", got)
	}
}

func TestPadRight_WithANSI(t *testing.T) {
	colored := "\033[31mhi\033[0m"
	got := padRight(colored, 5)
	// visible length is 2, so needs 3 spaces of padding
	if visibleLen(got) != 5 {
		t.Errorf("padRight with ANSI: visibleLen = %d, want 5", visibleLen(got))
	}
}
